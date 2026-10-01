// HELIOS-NET :: transport/goscan/goscan.go
// High-performance adaptive concurrent TCP port scanner & banner grabber in pure Go.
// Implements Bounded Worker Pool (Semaphore), non-blocking timeouts, and NDJSON streaming.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Version identifies the core build; the bridge reports it during health checks.
	Version = "HELIOS-NET Go Scanner 1.0.0 (pure stdlib)"

	// maxWorkers bounds concurrent dials so a wide range cannot exhaust file
	// descriptors or flood a target.
	maxWorkers = 300

	// scanTimeout bounds a single dial attempt.
	scanTimeout = 1200 * time.Millisecond

	// bannerTimeout bounds the greeting read on an already-open connection.
	bannerTimeout = 600 * time.Millisecond

	// bannerLimit caps how many bytes of a greeting are kept.
	bannerLimit = 256

	// commonPorts is the default sweep when the port argument is not parseable.
	commonPorts = "21,22,23,25,53,80,110,443,445,3306,3389,5432,8080"
)

type PortResult struct {
	Port      int    `json:"port"`
	Open      bool   `json:"open"`
	Banner    string `json:"banner,omitempty"`
	Service   string `json:"service,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Time      string `json:"time"`
}

type ErrorEnvelope struct {
	Status    string `json:"status"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Component string `json:"component"`
	Module    string `json:"module,omitempty"`
}

func emitEnvelope(code, message, module string) {
	env := ErrorEnvelope{
		Status:    "error",
		Code:      code,
		Message:   message,
		Component: "transport/goscan",
		Module:    module,
	}
	data, _ := json.Marshal(env)
	fmt.Fprintln(os.Stderr, string(data))
}

// sanitizeBanner keeps printable ASCII, replaces everything else with a space,
// trims, and caps the length. Extracted so the escaping rules can be unit tested
// without opening a socket, and so a hostile peer can neither inject control
// bytes into the NDJSON stream nor inflate a result record.
func sanitizeBanner(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return ' '
	}, raw)
	cleaned = strings.TrimSpace(cleaned)
	if len(cleaned) > bannerLimit {
		cleaned = cleaned[:bannerLimit]
	}
	return strings.TrimSpace(cleaned)
}

// grabBanner attempts to read a greeting banner from an open TCP connection with a strict timeout.
func grabBanner(conn net.Conn) (string, string) {
	_ = conn.SetReadDeadline(time.Now().Add(bannerTimeout))
	reader := bufio.NewReader(conn)

	// Check if service sends data first (like SSH, FTP, SMTP)
	buf := make([]byte, bannerLimit)
	n, err := reader.Read(buf)
	if err == nil && n > 0 {
		cleaned := sanitizeBanner(string(buf[:n]))
		if cleaned == "" {
			return "", ""
		}
		return cleaned, guessServiceFromBanner(cleaned)
	}
	return "", ""
}

func guessServiceFromBanner(banner string) string {
	lower := strings.ToLower(banner)
	// Order matters: the more specific database name must be tested before the
	// generic "db" substring, otherwise MariaDB is misreported.
	if strings.Contains(lower, "ssh") {
		return "ssh"
	}
	if strings.Contains(lower, "http") || strings.Contains(lower, "html") {
		return "http"
	}
	if strings.Contains(lower, "ftp") {
		return "ftp"
	}
	if strings.Contains(lower, "smtp") || strings.Contains(lower, "mail") {
		return "smtp"
	}
	if strings.Contains(lower, "mariadb") {
		return "mariadb"
	}
	if strings.Contains(lower, "mysql") {
		return "mysql"
	}
	if strings.Contains(lower, "postgres") {
		return "postgresql"
	}
	if strings.Contains(lower, "redis") {
		return "redis"
	}
	if strings.Contains(lower, "telnet") {
		return "telnet"
	}
	return "unknown"
}

// knownServices is every name either detector can produce. resolveService
// validates against it so the function is total: it does not have to trust its
// caller to hand it a name rather than a raw banner.
var knownServices = map[string]bool{
	// guessServiceFromBanner
	"ssh": true, "http": true, "ftp": true, "smtp": true, "mariadb": true,
	"mysql": true, "postgresql": true, "redis": true, "telnet": true,
	// guessServiceFromPort
	"dns": true, "https": true, "smb": true, "mongodb": true, "tcp": true,
}

// resolveService decides what a discovered port is reported as.
//
// The banner wins whenever the peer identified itself with a name this core
// recognises. Otherwise the well-known port is the only evidence available, and
// returning "" is not a neutral choice: Service carries `omitempty`, so an empty
// string deletes the key from the NDJSON entirely and the Python bridge reports
// service "" for a port that was just proven open.
//
// The empty case is the common one, not an edge case. HTTP waits for a request
// and never greets, and plenty of services behind a firewall complete the
// handshake silently. The previous code only fell back on "unknown", which is
// what a *present but unrecognised* banner produces, so the fallback never ran
// for any port that said nothing at all.
//
// Anything that is not a known name is treated as no name. Passing a raw
// attacker-controlled banner straight through would put a hostile string in a
// field a consumer reads as a service name, and the only thing that made that
// safe was `json.Marshal` escaping it by luck rather than by decision.
func resolveService(bannerService string, port int) string {
	if knownServices[bannerService] {
		return bannerService
	}
	return guessServiceFromPort(port)
}

func guessServiceFromPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80, 8080, 8000:
		return "http"
	case 443, 8443:
		return "https"
	case 445:
		return "smb"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	default:
		return "tcp"
	}
}

// defaultPorts is the sweep used when the argument carries no usable port.
func defaultPorts() []int {
	ports := make([]int, 0, 16)
	for _, p := range strings.Split(commonPorts, ",") {
		if val, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && validPort(val) {
			ports = append(ports, val)
		}
	}
	return ports
}

// validPort rejects values that cannot be dialled.
func validPort(p int) bool { return p >= 1 && p <= 65535 }

// dedupePorts removes repeats while preserving first-seen order. Without this,
// "80,80,443" and overlapping ranges such as "1-100,50-200" scan the same port
// twice, which double-counts the port in the result set and makes the reported
// count disagree with the number of distinct open ports.
func dedupePorts(ports []int) []int {
	if len(ports) < 2 {
		return ports
	}
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// parsePorts accepts "80", "1-1000", "80,443" or a fallback keyword.
//
// A well-formed but reversed range ("9-2") is a user error and yields an empty
// list so the caller reports PARSE_ERROR. Input that is not port-shaped at all
// falls back to the common sweep. The previous implementation tested for a bare
// "-" before checking the numbers, so any argument containing a hyphen
// ("not-a-port") silently scanned zero ports and reported success.
func parsePorts(arg string) []int {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return defaultPorts()
	}

	// Named presets are handled explicitly. Previously any word fell through to
	// defaultPorts(), so `goscan host all` scanned 13 ports and reported success
	// instead of the 65535 the user asked for. A silently incomplete sweep is
	// worse than a slow one, because the report looks complete.
	switch strings.ToLower(trimmed) {
	case "common", "default":
		return defaultPorts()
	case "all", "full", "1-65535":
		all := make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			all = append(all, i)
		}
		return all
	}

	if strings.Contains(trimmed, ",") {
		var ports []int
		for _, p := range strings.Split(trimmed, ",") {
			expanded, _ := parsePortToken(p)
			ports = append(ports, expanded...)
		}
		if len(ports) > 0 {
			return dedupePorts(ports)
		}
		return defaultPorts()
	}

	if ports, recognized := parsePortToken(trimmed); recognized {
		return ports
	}

	return defaultPorts()
}

// parsePortToken expands one comma-separated element, which is either a single
// port ("443") or a range ("1-1024"). The bool reports whether the text was
// recognized as a port specification at all, which is what separates a typo from
// a deliberate request:
//
//   - ("1-100", true)   a range
//   - ("100-1", true)  recognized but reversed, so it yields no ports
//   - ("0", false)     a number that is out of port range
//   - ("nope", false)  not a port spec, so the caller may fall back
//
// The comma list previously accepted bare integers only, so "1-100,50-200"
// dropped both tokens, left the list empty, and fell through to defaultPorts().
// That returned 13 common ports for a request that reads as a 200-port sweep,
// and the caller saw a successful scan. Ranges are now parsed in both positions
// from this one function, so the two paths cannot drift apart again.
func parsePortToken(token string) ([]int, bool) {
	t := strings.TrimSpace(token)
	if t == "" {
		return nil, false
	}

	if val, err := strconv.Atoi(t); err == nil {
		if validPort(val) {
			return []int{val}, true
		}
		// A number outside 1-65535 is a bad value, not a deliberate
		// no-ports request, so the caller falls back to the default list.
		return nil, false
	}

	parts := strings.Split(t, "-")
	if len(parts) != 2 {
		return nil, false
	}
	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return nil, false
	}
	// Both halves are numbers: treat this as a deliberate range request. A
	// reversed range is a typo rather than a request to wrap, and it resolves to
	// no ports instead of falling back to the default list.
	if start > end {
		return nil, true
	}

	// Clamp to the valid port range BEFORE allocating or looping.
	//
	// Sizing the slice from the raw request meant "1-999999999" asked for a
	// billion-element capacity, roughly 8 GB of virtual address space, and then
	// iterated a billion times to keep the 65535 ports that were actually valid.
	// On a 64-bit host the allocation is reserved rather than faulted in, so it
	// appeared to "work" while burning seconds of CPU per scan, and on a
	// memory-limited runner it would have failed outright. validPort() filtered
	// the values, but the allocation and the loop were already unbounded.
	lo, hi := start, end
	if lo < 1 {
		lo = 1
	}
	if hi > 65535 {
		hi = 65535
	}
	if lo > hi {
		// The whole range is outside the valid port space, e.g. "70000-80000".
		return nil, true
	}
	ports := make([]int, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		ports = append(ports, i)
	}
	return ports, true
}

func main() {
	args := os.Args[1:]

	// Control subcommands: a core that cannot prove it works is a liability, and
	// the previous build shipped a binary that deadlocked on every real call
	// because nothing ever executed it. These run entirely offline.
	switch {
	case len(args) == 1 && args[0] == "selftest":
		os.Exit(runSelftest())
	case len(args) == 1 && (args[0] == "version" || args[0] == "--version"):
		fmt.Printf("%s\n", Version)
		os.Exit(0)
	case len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help"):
		usage()
		os.Exit(0)
	}

	if len(args) < 2 {
		emitEnvelope("PARSE_ERROR", "usage: goscan <target-ip> <ports: 80 or 1-1000 or 80,443>", "goscan")
		usage()
		os.Exit(2)
	}

	targetIP := args[0]
	portArg := args[1]
	ports := parsePorts(portArg)
	if len(ports) == 0 {
		emitEnvelope("PARSE_ERROR", "no valid ports in argument: "+portArg, "goscan")
		os.Exit(2)
	}

	resultsChan, wait := startScan(targetIP, ports, scanTimeout)

	encoder := json.NewEncoder(os.Stdout)
	for res := range resultsChan {
		if res.Open {
			if err := encoder.Encode(res); err != nil {
				emitEnvelope("IO_ERROR", "failed writing result stream: "+err.Error(), "goscan")
				os.Exit(3)
			}
		}
	}
	wait()
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  goscan <target-ip> <ports>   scan (80, 1-1000, 80,443, 'common' or 'all')")
	fmt.Fprintln(os.Stderr, "  goscan selftest               run offline internal checks")
	fmt.Fprintln(os.Stderr, "  goscan version                print the version string")
}

// scanPort dials one port and reports it. It runs on a pool worker rather than
// on its own goroutine, so it takes no semaphore and no WaitGroup: the number of
// workers already bounds how many of these run at once. A per-port semaphore
// here would be a second, weaker bound that buys nothing.
func scanPort(ip string, port int, timeout time.Duration, results chan<- PortResult) {
	// JoinHostPort brackets IPv6 literals, so IPv6 targets are dialable
	// instead of being mis-parsed as host:port.
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	latency := time.Since(start).Milliseconds()

	if err == nil {
		defer conn.Close()
		banner, service := grabBanner(conn)
		results <- PortResult{
			Port:      port,
			Open:      true,
			Banner:    banner,
			Service:   resolveService(service, port),
			LatencyMs: latency,
			Time:      time.Now().Format(time.RFC3339),
		}
	} else {
		results <- PortResult{
			Port: port,
			Open: false,
		}
	}
}

// startScan dispatches the sweep over a fixed set of workers and returns the
// result stream plus a wait function. Extracted from main so tests can drive the
// real scan path.
//
// The pool size is the concurrency bound. An earlier version spawned one
// goroutine per port and had them contend for a counting semaphore, which capped
// concurrent *dials* but not goroutines: a full sweep measured 55252 live
// goroutines against maxWorkers=300, so tens of megabytes of stacks went into
// running three hundred connections. Workers pulling from a shared channel bound
// both numbers by the same constant, and pool_bounds_test.go holds that bound.
//
// resultsChan is buffered to the size of the sweep, so a worker can never block
// on a result send even if the consumer stops reading, and no drain goroutine
// is needed for it.
func startScan(targetIP string, ports []int, timeout time.Duration) (chan PortResult, func()) {
	// Nothing to scan: close the stream up front, otherwise a consumer ranging
	// over it waits for a closer that zero workers would never run.
	if len(ports) == 0 {
		resultsChan := make(chan PortResult)
		close(resultsChan)
		return resultsChan, func() {}
	}

	// Pre-filled and closed, so workers only ever range over it. Buffering the
	// whole sweep keeps the port hand-off non-blocking without a feeder
	// goroutine, which is the allocation the fix is meant to remove.
	work := make(chan int, len(ports))
	for _, p := range ports {
		work <- p
	}
	close(work)

	workers := maxWorkersFor(len(ports))
	resultsChan := make(chan PortResult, len(ports))

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for port := range work {
				scanPort(targetIP, port, timeout, resultsChan)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	return resultsChan, wg.Wait
}

// maxWorkersFor caps concurrency at the pool size without ever under-filling the
// semaphore, which is what previously caused the deadlock.
func maxWorkersFor(ports int) int {
	if ports < maxWorkers {
		return ports
	}
	return maxWorkers
}
