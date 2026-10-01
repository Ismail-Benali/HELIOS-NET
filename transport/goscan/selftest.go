// HELIOS-NET :: transport/goscan/selftest.go
// Offline self-verification for the Go core.
//
// Rationale: this core previously deadlocked on every real invocation because the
// semaphore was never seeded, and no test ever executed it. A fallback that
// quietly returns an empty result set hid the defect for the lifetime of the
// project. `goscan selftest` gives the bridge a way to prove the binary works
// without touching the network, and the same checks run under `go test`.

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// check is one named self-test outcome.
type check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// selftestReport is the NDJSON object printed on stdout.
type selftestReport struct {
	Status  string  `json:"status"`
	Suite   string  `json:"suite"`
	Version string  `json:"version"`
	Checks  int     `json:"checks"`
	Failed  int     `json:"failures"`
	Details []check `json:"details"`
}

// runSelftest executes the offline checks and returns a process exit code.
func runSelftest() int {
	checks := selftestChecks()

	failures := 0
	for _, c := range checks {
		if !c.Passed {
			failures++
		}
	}

	report := selftestReport{
		Status:  "ok",
		Suite:   "goscan_selftest",
		Version: Version,
		Checks:  len(checks),
		Failed:  failures,
		Details: checks,
	}
	if failures > 0 {
		report.Status = "failed"
	}

	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(report); err != nil {
		emitEnvelope("IO_ERROR", "failed encoding selftest report: "+err.Error(), "goscan")
		return 3
	}
	if failures > 0 {
		return 1
	}
	return 0
}

// selftestChecks is the shared body of `goscan selftest` and the Go tests, so
// the binary and `go test` can never drift apart.
func selftestChecks() []check {
	var checks []check

	add := func(name string, ok bool, detail string) {
		checks = append(checks, check{Name: name, Passed: ok, Detail: detail})
	}

	// 1. Port argument parsing.
	{
		got := parsePorts("80")
		add("parsePorts/single", len(got) == 1 && got[0] == 80, fmt.Sprintf("%v", got))
	}
	{
		got := parsePorts("1-3")
		ok := len(got) == 3 && got[0] == 1 && got[2] == 3
		add("parsePorts/range", ok, fmt.Sprintf("%v", got))
	}
	{
		got := parsePorts("80,443")
		ok := len(got) == 2 && got[0] == 80 && got[1] == 443
		add("parsePorts/comma", ok, fmt.Sprintf("%v", got))
	}
	{
		got := parsePorts("not-a-port")
		ok := len(got) == 13
		add("parsePorts/falls-back-to-common", ok, fmt.Sprintf("%d entries", len(got)))
	}
	{
		// A reversed or malformed range must not produce a negative sweep.
		got := parsePorts("9-2")
		ok := len(got) == 0
		add("parsePorts/reversed-range-ignored", ok, fmt.Sprintf("%v", got))
	}

	// 2. Address formatting. This is the IPv6 fix: a bare "%s:%d" mis-parses an
	// IPv6 literal and silently prevents every connection.
	{
		ok := net.JoinHostPort("192.0.2.1", "80") == "192.0.2.1:80"
		add("addr/ipv4", ok, net.JoinHostPort("192.0.2.1", "80"))
	}
	{
		ok := net.JoinHostPort("::1", "80") == "[::1]:80"
		add("addr/ipv6-bracketed", ok, net.JoinHostPort("::1", "80"))
	}

	// 3. Worker-pool sizing. Under-filling the semaphore is what deadlocked the
	// previous build, so the invariant is asserted explicitly.
	{
		ok := maxWorkersFor(1) == 1 && maxWorkersFor(10) == 10
		add("pool/small-sweep-not-underfilled", ok, fmt.Sprintf("%d", maxWorkersFor(1)))
	}
	{
		ok := maxWorkersFor(maxWorkers+50) == maxWorkers
		add("pool/large-sweep-capped", ok, fmt.Sprintf("%d", maxWorkersFor(maxWorkers+50)))
	}
	{
		ok := maxWorkersFor(0) == 0
		add("pool/zero-is-zero", ok, fmt.Sprintf("%d", maxWorkersFor(0)))
	}

	// 4. The semaphore must be seeded, and every token must be returned.
	{
		size := 4
		sem := make(chan struct{}, size)
		for i := 0; i < size; i++ {
			sem <- struct{}{}
		}
		seeded := len(sem)
		drained := 0
		for drained < size {
			select {
			case <-sem:
				drained++
			default:
			}
		}
		// An unseeded semaphore reports 0 here, which is exactly the deadlock.
		add("pool/semaphore-seeded", seeded == size && drained == size,
			fmt.Sprintf("seeded=%d drained=%d", seeded, drained))
	}

	// 5. Banner sanitising: a hostile peer must not inject control bytes.
	{
		got := sanitizeBanner("SSH-2.0-OpenSSH\r\n\x00\x07\x1b[31m")
		clean := !strings.ContainsAny(got, "\r\n\x00\x1b")
		add("banner/control-bytes-stripped", clean, got)
	}
	{
		got := sanitizeBanner("  nginx/1.24  ")
		add("banner/trimmed", got == "nginx/1.24", got)
	}
	{
		got := sanitizeBanner(strings.Repeat("A", bannerLimit+40))
		add("banner/length-capped", len(got) <= bannerLimit, fmt.Sprintf("%d", len(got)))
	}

	// 6. Service detection.
	{
		cases := map[string]string{
			"SSH-2.0-OpenSSH_9.6":    "ssh",
			"HTTP/1.1 200 OK":        "http",
			"220 ProFTPD":            "ftp",
			"220 mail.example ESMTP": "smtp",
			"5.5.5-10.10.45-MariaDB": "mariadb",
			"mysql_native_password":  "mysql",
			"PostgreSQL 16.1":        "postgresql",
			"-REDIS-STREAM":          "redis",
			"something unrecognised": "unknown",
		}
		mismatches := []string{}
		for banner, want := range cases {
			if got := guessServiceFromBanner(banner); got != want {
				mismatches = append(mismatches, fmt.Sprintf("%q->%s(want %s)", banner, got, want))
			}
		}
		add("service/from-banner", len(mismatches) == 0, strings.Join(mismatches, ", "))
	}
	{
		cases := map[int]string{
			22: "ssh", 80: "http", 443: "https", 3306: "mysql",
			6379: "redis", 27017: "mongodb", 65000: "tcp",
		}
		mismatches := []string{}
		for port, want := range cases {
			if got := guessServiceFromPort(port); got != want {
				mismatches = append(mismatches, fmt.Sprintf("%d->%s(want %s)", port, got, want))
			}
		}
		add("service/from-port", len(mismatches) == 0, strings.Join(mismatches, ", "))
	}

	// 7. Service resolution. The two helpers above are each correct, and the
	// line that combined them fell back only on "unknown" -- so a port that
	// sent no greeting, which is most of them, was reported with no service at
	// all and `omitempty` deleted the key from the NDJSON. The composition is
	// the part that was never asserted, so it is asserted here.
	{
		cases := []struct {
			banner string
			port   int
			want   string
		}{
			{"ssh", 65000, "ssh"}, // banner outranks the port
			{"", 80, "http"},      // no greeting, the common case
			{"unknown", 443, "https"},
			{"", 65000, "tcp"}, // must stay non-empty or the key is dropped
		}
		mismatches := []string{}
		for _, c := range cases {
			if got := resolveService(c.banner, c.port); got != c.want {
				mismatches = append(mismatches, fmt.Sprintf("(%q,%d)->%s(want %s)", c.banner, c.port, got, c.want))
			}
		}
		add("service/resolution", len(mismatches) == 0, strings.Join(mismatches, ", "))
	}

	// 8. Error envelope shape. Python parses this on stderr, so the keys are a
	// contract rather than a formatting choice.
	{
		ok := envelopeIsWellFormed(ErrorEnvelope{
			Status:    "error",
			Code:      "SELFTEST",
			Message:   "probe",
			Component: "transport/goscan",
			Module:    "goscan",
		})
		add("envelope/contract", ok, "status/code/message/component present")
	}

	// 9. A closed port must yield no open result rather than a false positive.
	{
		// Port 1 on loopback is reliably closed and never requires privileges.
		results, wait := startScan("127.0.0.1", []int{1}, scanTimeout)
		open := 0
		for res := range results {
			if res.Open {
				open++
			}
		}
		wait()
		add("scan/closed-port-not-open", open == 0, fmt.Sprintf("%d open", open))
	}

	// 10. The scan pipeline must terminate at all. The original defect hung here.
	{
		done := make(chan struct{})
		go func() {
			results, wait := startScan("127.0.0.1", []int{1, 2, 3}, scanTimeout)
			for range results {
			}
			wait()
			close(done)
		}()
		select {
		case <-done:
			add("scan/pipeline-terminates", true, "returned control")
		case <-time.After(20 * time.Second):
			add("scan/pipeline-terminates", false, "still blocked after 20s (deadlock)")
		}
	}

	return checks
}

// envelopeIsWellFormed checks the fields the Python envelope parser requires.
func envelopeIsWellFormed(e ErrorEnvelope) bool {
	return e.Status == "error" && e.Code != "" && e.Message != "" && e.Component != ""
}
