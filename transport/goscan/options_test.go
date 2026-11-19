// Tests for the scan options added with pacing, retries and reason reporting.
//
// The dial classifier and the request-building helpers are pure functions, so
// they are tested without a network. The refusal test uses a listener that is
// closed before the scan, which is the one failure a local test can produce
// deterministically.

package main

import (
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseScanArgsDefaults(t *testing.T) {
	_, _, opts, err := parseScanArgs([]string{"example.test", "80"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.timeout != scanTimeout || opts.retries != 0 || opts.ratePerSec != 0 {
		t.Fatalf("unexpected defaults: %+v", opts)
	}
}

func TestParseScanArgsAcceptsTuningFlags(t *testing.T) {
	_, _, opts, err := parseScanArgs([]string{
		"example.test", "1-3", "--timeout-ms", "250", "--retries", "2", "--rate", "40",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.timeout != 250*time.Millisecond || opts.retries != 2 || opts.ratePerSec != 40 {
		t.Fatalf("flags not applied: %+v", opts)
	}
}

func TestParseScanArgsRejectsUnknownAndMissingValues(t *testing.T) {
	cases := [][]string{
		{"example.test", "80", "--nope", "1"},
		{"example.test", "80", "--retries"},
		{"example.test", "80", "--timeout-ms", "0"},
		{"example.test", "80", "--timeout-ms", "600001"},
		{"example.test", "80", "--retries", "6"},
		{"example.test", "80", "--retries", "-1"},
		{"example.test", "80", "--rate", "100001"},
		{"example.test"},
	}
	for _, args := range cases {
		if _, _, _, err := parseScanArgs(args); err == nil {
			t.Errorf("parseScanArgs(%v) accepted an invalid value", args)
		}
	}
}

func TestClassifyDialError(t *testing.T) {
	timeout := &net.DNSError{Err: "timed out", IsTimeout: true}
	refusedErrno := syscall.ECONNREFUSED
	unreachableErrno := syscall.EHOSTUNREACH
	if runtime.GOOS == "windows" {
		refusedErrno = 10061
		unreachableErrno = 10065
	}
	refused := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: os.NewSyscallError("connect", refusedErrno),
	}
	unreachable := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: os.NewSyscallError("connect", unreachableErrno),
	}
	cases := map[string]struct {
		err  error
		want string
	}{
		"nil":         {nil, "open"},
		"timeout":     {timeout, "timeout"},
		"refused":     {refused, "refused"},
		"unreachable": {unreachable, "unreachable"},
		"other":       {errors.New("boom"), "error"},
	}
	for name, tc := range cases {
		if got := classifyDialError(tc.err); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

func TestHTTPHostIncludesNonDefaultPortAndBracketsIPv6(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"example.test", 80, "example.test"},
		{"example.test", 443, "example.test"},
		{"example.test", 8080, "example.test:8080"},
		{"2001:db8::1", 8443, "[2001:db8::1]:8443"},
	}
	for _, tc := range cases {
		if got := httpHost(tc.host, tc.port); got != tc.want {
			t.Errorf("httpHost(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestSafeHostValueRejectsHeaderInjection(t *testing.T) {
	for _, bad := range []string{"", "a\r\nX: y", "a\nb", "a b", "a/b", "a\x00b"} {
		if safeHostValue(bad) {
			t.Errorf("safeHostValue(%q) accepted an unsafe target", bad)
		}
	}
	for _, good := range []string{"example.test", "127.0.0.1", "2001:db8::1", "fe80::1%eth0"} {
		if !safeHostValue(good) {
			t.Errorf("safeHostValue(%q) rejected a dialable target", good)
		}
	}
}

func TestTLSServerNameOmitsIPLiterals(t *testing.T) {
	if got := tlsServerName("192.0.2.1"); got != "" {
		t.Errorf("IP target produced SNI %q", got)
	}
	if got := tlsServerName("2001:db8::1"); got != "" {
		t.Errorf("IPv6 target produced SNI %q", got)
	}
	if got := tlsServerName("example.test."); got != "example.test" {
		t.Errorf("trailing dot not trimmed: %q", got)
	}
}

func TestRateLimiterHasNoIntervalWhenDisabled(t *testing.T) {
	if newRateLimiter(0) != nil {
		t.Fatal("rate 0 must disable pacing")
	}
	if got := newRateLimiter(10).interval; got != 100*time.Millisecond {
		t.Fatalf("rate 10 interval = %s, want 100ms", got)
	}
	if got := newRateLimiter(maxRatePerSecond).interval; got != 10*time.Microsecond {
		t.Fatalf("clamped interval = %s, want 10us", got)
	}
}

func TestRefusalIsNotRetried(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	opts := defaultScanOptions()
	opts.timeout = 200 * time.Millisecond
	opts.retries = 3

	results := make(chan PortResult, 1)
	scanPortWithOptions("127.0.0.1", port, opts, nil, results)
	close(results)

	res := <-results
	if res.Open {
		t.Fatalf("port %d was unexpectedly open", port)
	}
	if res.Reason != "refused" {
		t.Fatalf("reason = %q, want refused", res.Reason)
	}
	if res.Attempts != 0 {
		t.Fatalf("a refusal was retried: attempts = %d", res.Attempts)
	}
}

func TestRetryCountIsReportedOnlyWhenUsed(t *testing.T) {
	if got := attemptsIfRetried(1); got != 0 {
		t.Fatalf("single attempt reported as %d", got)
	}
	if got := attemptsIfRetried(3); got != 3 {
		t.Fatalf("three attempts reported as %d", got)
	}
}

func TestScanOptionsNormaliseBounds(t *testing.T) {
	base := defaultScanOptions()
	bad := []scanOptions{
		{timeout: 0},
		{timeout: maxScanTimeout + time.Second},
		{timeout: time.Second, retries: -1},
		{timeout: time.Second, retries: maxRetries + 1},
		{timeout: time.Second, ratePerSec: -1},
		{timeout: time.Second, ratePerSec: maxRatePerSecond + 1},
	}
	for _, opts := range bad {
		if _, err := opts.normalise(); err == nil {
			t.Errorf("normalise(%+v) accepted invalid options", opts)
		}
	}
	if _, err := base.normalise(); err != nil {
		t.Fatalf("default options rejected: %v", err)
	}
}

func TestBannerSanitizerStillStripsControlBytes(t *testing.T) {
	got := sanitizeBanner("SSH-2.0\r\n\x00evil\xff")
	if strings.ContainsAny(got, "\r\n\x00") {
		t.Fatalf("control bytes survived: %q", got)
	}
}
