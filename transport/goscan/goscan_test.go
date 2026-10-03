// HELIOS-NET :: transport/goscan/goscan_test.go
// Unit and integration tests for the Go core.
//
// This core previously had no tests at all, and shipped a binary that
// deadlocked on every invocation. The shared `selftestChecks` body means the
// offline guarantees asserted here are exactly the ones `goscan selftest`
// reports to the Python bridge, so the two cannot drift.

package main

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------- shared selftest

// TestSelftestSuitePasses runs the same body the binary exposes and fails if any
// check does, so a regression in either surface is caught here.
func TestSelftestSuitePasses(t *testing.T) {
	for _, c := range selftestChecks() {
		if !c.Passed {
			t.Errorf("selftest check %q failed: %s", c.Name, c.Detail)
		}
	}
}

// --------------------------------------------------------- port parsing

func TestParsePortsSingle(t *testing.T) {
	got := parsePorts("80")
	if len(got) != 1 || got[0] != 80 {
		t.Fatalf("got %v, want [80]", got)
	}
}

func TestParsePortsRange(t *testing.T) {
	got := parsePorts("1-3")
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("got %v, want [1 2 3]", got)
	}
}

func TestParsePortsCommaList(t *testing.T) {
	got := parsePorts("80,443")
	if len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("got %v, want [80 443]", got)
	}
}

// TestParsePortsIgnoresInvalidEntriesInAList keeps one bad value from discarding
// the whole sweep.
func TestParsePortsIgnoresInvalidEntriesInAList(t *testing.T) {
	got := parsePorts("80,notaport,443")
	if len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("got %v, want [80 443]", got)
	}
}

// TestParsePortsFallsBackOnGarbage is the regression test for the original
// defect: a hyphen in non-numeric input hijacked the range branch, so
// "not-a-port" scanned zero ports and still reported success.
func TestParsePortsFallsBackOnGarbage(t *testing.T) {
	for _, arg := range []string{"not-a-port", "common", "--", "???", "80-"} {
		got := parsePorts(arg)
		if len(got) != 13 {
			t.Errorf("parsePorts(%q) = %d entries, want the 13 common ports", arg, len(got))
		}
	}
}

func TestParsePortsEmptyArgumentFallsBack(t *testing.T) {
	if got := parsePorts(""); len(got) != 13 {
		t.Fatalf("got %d entries, want 13", len(got))
	}
}

func TestParsePortsWhitespaceTolerated(t *testing.T) {
	got := parsePorts(" 80 , 443 ")
	if len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("got %v, want [80 443]", got)
	}
}

// TestParsePortsReversedRangeIsAnError: a deliberate but inverted range yields
// nothing so the caller can report PARSE_ERROR, rather than silently sweeping
// something the operator did not ask for.
func TestParsePortsReversedRangeIsAnError(t *testing.T) {
	if got := parsePorts("9-2"); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestParsePortsRejectsOutOfRangeValues(t *testing.T) {
	for _, arg := range []string{"0", "65536", "70000"} {
		if got := parsePorts(arg); len(got) != 13 {
			t.Errorf("parsePorts(%q) should fall back, got %v", arg, got)
		}
	}
	if got := parsePorts("65535"); len(got) != 1 || got[0] != 65535 {
		t.Errorf("65535 is a valid port, got %v", got)
	}
}

func TestValidPortBoundaries(t *testing.T) {
	cases := map[int]bool{0: false, 1: true, 65535: true, 65536: false, -1: false}
	for port, want := range cases {
		if got := validPort(port); got != want {
			t.Errorf("validPort(%d) = %v, want %v", port, got, want)
		}
	}
}

// -------------------------------------------------------- worker pool

// TestSemaphoreIsSeeded is the direct regression test for the deadlock: an
// unseeded channel leaves every worker blocked on receive.
func TestSemaphoreIsSeeded(t *testing.T) {
	results, wait := startScan("127.0.0.1", []int{1}, scanTimeout)

	done := make(chan struct{})
	go func() {
		for range results {
		}
		wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("scan pipeline deadlocked: the semaphore was never seeded")
	}
}

func TestMaxWorkersFor(t *testing.T) {
	cases := map[int]int{0: 0, 1: 1, 5: 5, maxWorkers: maxWorkers, maxWorkers + 1: maxWorkers}
	for ports, want := range cases {
		if got := maxWorkersFor(ports); got != want {
			t.Errorf("maxWorkersFor(%d) = %d, want %d", ports, got, want)
		}
	}
}

// TestMaxWorkersTracksTheSweep states the real invariant: the pool matches the
// sweep up to the cap and is then held at the cap. An earlier version of this
// file wrongly demanded pool >= ports for every sweep, which would forbid
// bounding concurrency at all.
func TestMaxWorkersTracksTheSweep(t *testing.T) {
	for ports := 0; ports <= maxWorkers+10; ports++ {
		got := maxWorkersFor(ports)
		want := ports
		if want > maxWorkers {
			want = maxWorkers
		}
		if got != want {
			t.Fatalf("maxWorkersFor(%d) = %d, want %d", ports, got, want)
		}
	}
}

// TestPoolReturnsEveryResult: a sweep of N ports must produce N results, so no
// worker is lost or double-counted.
func TestPoolReturnsEveryResult(t *testing.T) {
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	results, wait := startScan("127.0.0.1", ports, scanTimeout)
	count := 0
	for range results {
		count++
	}
	wait()
	if count != len(ports) {
		t.Fatalf("got %d results for %d ports", count, len(ports))
	}
}

func TestPoolHandlesWideSweep(t *testing.T) {
	var ports []int
	for p := 1; p <= 120; p++ {
		ports = append(ports, p)
	}
	results, wait := startScan("127.0.0.1", ports, scanTimeout)
	count := 0
	for range results {
		count++
	}
	wait()
	if count != len(ports) {
		t.Fatalf("got %d results for %d ports", count, len(ports))
	}
}

// ------------------------------------------------------------- banner

func TestSanitizeBannerStripsControlBytes(t *testing.T) {
	got := sanitizeBanner("SSH-2.0-OpenSSH\r\n\x00\x07\x1b[31m")
	if strings.ContainsAny(got, "\r\n\x00\x1b") {
		t.Fatalf("control bytes survived: %q", got)
	}
}

func TestSanitizeBannerTrims(t *testing.T) {
	if got := sanitizeBanner("  nginx/1.24  "); got != "nginx/1.24" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeBannerCapsLength(t *testing.T) {
	got := sanitizeBanner(strings.Repeat("A", bannerLimit*3))
	if len(got) != bannerLimit {
		t.Fatalf("got %d bytes, want %d", len(got), bannerLimit)
	}
}

func TestSanitizeBannerOfPureControlIsEmpty(t *testing.T) {
	if got := sanitizeBanner("\x00\x01\x02"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

// TestGrabBannerReadsGreeting exercises the real socket path.
func TestGrabBannerReadsGreeting(t *testing.T) {
	ln := newEchoServer(t, "SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
	defer func() { _ = ln.Close() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	banner, service := grabBanner(conn)
	if banner != "SSH-2.0-OpenSSH_9.6p1 Ubuntu" {
		t.Errorf("banner = %q", banner)
	}
	if service != "ssh" {
		t.Errorf("service = %q, want ssh", service)
	}
}

// TestGrabBannerSilentServer proves the read timeout is honoured rather than
// hanging the worker forever.
func TestGrabBannerSilentServer(t *testing.T) {
	ln := mustListen(t)
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Hold the connection open without ever writing a greeting.
		time.Sleep(2 * bannerTimeout)
		_ = conn.Close()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if banner, _ := grabBanner(conn); banner != "" {
			t.Errorf("expected empty banner, got %q", banner)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("grabBanner blocked past its deadline")
	}
}

// ------------------------------------------------------------- service

func TestResolveService(t *testing.T) {
	cases := []struct {
		banner string
		port   int
		want   string
		why    string
	}{
		{"ssh", 65000, "ssh", "a banner outranks the port, even an unknown port"},
		{"", 80, "http", "no greeting: the common case, and the one that regressed"},
		{"unknown", 443, "https", "unrecognised banner falls back"},
		{"", 22, "ssh", "empty is not the same as unknown"},
		{"", 65000, "tcp", "even an unnamed port gets a label, or the key is dropped"},
		{"mysql", 3306, "mysql", "banner and port agree"},
		{"mariadb", 3306, "mariadb", "a banner can rename the port hint"},
	}
	for _, c := range cases {
		if got := resolveService(c.banner, c.port); got != c.want {
			t.Errorf("resolveService(%q, %d) = %q, want %q: %s", c.banner, c.port, got, c.want, c.why)
		}
	}
}

func TestResolveServiceIsNeverEmpty(t *testing.T) {
	// Service is `omitempty`, so an empty return deletes the key from the
	// NDJSON and the Python bridge has nothing to report about an open port.
	for _, port := range []int{1, 22, 80, 443, 1024, 65000, 65535} {
		for _, banner := range []string{"", "unknown"} {
			if got := resolveService(banner, port); got == "" {
				t.Errorf("resolveService(%q, %d) = %q", banner, port, got)
			}
		}
	}
}

func TestGuessServiceFromBanner(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_9.6":    "ssh",
		"HTTP/1.1 200 OK":        "http",
		"<!DOCTYPE html>":        "http",
		"220 ProFTPD Server":     "ftp",
		"220 mail.example ESMTP": "smtp",
		"5.5.5-10.10.45-MariaDB": "mariadb",
		"mysql_native_password":  "mysql",
		"PostgreSQL 16.1":        "postgresql",
		"-REDIS-STREAM":          "redis",
		"Telnet data":            "telnet",
		"something unrecognised": "unknown",
		"":                       "unknown",
	}
	for banner, want := range cases {
		if got := guessServiceFromBanner(banner); got != want {
			t.Errorf("guessServiceFromBanner(%q) = %q, want %q", banner, got, want)
		}
	}
}

func TestGuessServiceFromBannerIsCaseInsensitive(t *testing.T) {
	for _, banner := range []string{"ssh-2.0-openssh", "SSH-2.0-OpenSSH", "Ssh-2.0"} {
		if got := guessServiceFromBanner(banner); got != "ssh" {
			t.Errorf("guessServiceFromBanner(%q) = %q", banner, got)
		}
	}
}

func TestGuessServiceFromPort(t *testing.T) {
	cases := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 443: "https", 445: "smb", 3306: "mysql",
		5432: "postgresql", 6379: "redis", 27017: "mongodb", 65000: "tcp",
	}
	for port, want := range cases {
		if got := guessServiceFromPort(port); got != want {
			t.Errorf("guessServiceFromPort(%d) = %q, want %q", port, got, want)
		}
	}
}

// ------------------------------------------------------------- envelope

func TestErrorEnvelopeJSONShape(t *testing.T) {
	data, err := json.Marshal(ErrorEnvelope{
		Status:    "error",
		Code:      "EDR_BLOCKED",
		Message:   "blocked",
		Component: "transport/goscan",
		Module:    "goscan",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The Python parser in core/envelope.py keys on exactly these names.
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"status", "code", "message", "component"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("envelope missing key %q: %s", key, data)
		}
	}
	if decoded["status"] != "error" {
		t.Errorf("status = %v, want error", decoded["status"])
	}
}

func TestPortResultOmitsEmptyBanner(t *testing.T) {
	data, err := json.Marshal(PortResult{Port: 80, Open: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "banner") {
		t.Errorf("empty banner should be omitted: %s", data)
	}
	if !strings.Contains(string(data), `"port":80`) {
		t.Errorf("missing port field: %s", data)
	}
}

func TestVersionStringIsSet(t *testing.T) {
	if !strings.Contains(Version, "Go Scanner") {
		t.Errorf("Version = %q", Version)
	}
}

// --------------------------------------------------------------- helpers

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// newEchoServer accepts a single connection and writes `greeting` to it.
func newEchoServer(t *testing.T, greeting string) net.Listener {
	t.Helper()
	ln := mustListen(t)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		writer := bufio.NewWriter(conn)
		_, _ = writer.WriteString(greeting)
		_ = writer.Flush()
		time.Sleep(100 * time.Millisecond)
	}()
	return ln
}
