// HELIOS-NET :: transport/goscan/service_resolution_test.go
// Regression cover for the service-resolution decision made when a port is scanned.
//
// Why this file exists
// --------------------
// The core had 37 unit tests, four fuzzers and a 21-check selftest, and the
// service a discovered port was reported as was still wrong for the most
// common case. Both halves were tested individually and both were correct:
//
//	guessServiceFromBanner("SSH-2.0-...")  -> "ssh"     (TestGuessServiceFromBanner)
//	guessServiceFromPort(80)               -> "http"    (TestGuessServiceFromPort)
//
// What decided between them was not:
//
//	if service == "unknown" { service = guessServiceFromPort(port) }
//
// grabBanner returns ("", "") whenever the peer sends no greeting, which is
// the majority of open ports: HTTP waits for a request, and anything behind a
// firewall that completes the handshake says nothing. Empty is not "unknown",
// so the port-based hint never ran. Because Service carries `omitempty`, the
// key then vanished from the NDJSON entirely and the Python bridge reported
// service "" for a port it had just proven was open.
//
// The suite reported full health throughout, because the untested line was the
// composition, not either component.

package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// silentServer accepts a connection and never writes, which is what a
// request-waiting service looks like to a banner grabber.
func silentServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(2 * bannerTimeout)
				_ = c.Close()
			}(conn)
		}
	}()
	return ln
}

// scanSingle drives the real scan path against 127.0.0.1 on the listener's
// port and returns the single result.
func scanSingle(t *testing.T, ln net.Listener) PortResult {
	t.Helper()
	port := ln.Addr().(*net.TCPAddr).Port

	results, wait := startScan("127.0.0.1", []int{port}, scanTimeout)
	var got []PortResult
	for res := range results {
		got = append(got, res)
	}
	wait()

	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if !got[0].Open {
		t.Fatalf("listener reported closed: %+v", got[0])
	}
	return got[0]
}

func TestSilentServiceFallsBackToThePortHint(t *testing.T) {
	ln := silentServer(t)
	defer func() { _ = ln.Close() }()

	res := scanSingle(t, ln)
	if res.Service == "" {
		t.Errorf("service is empty for an open port with no greeting; "+
			"the port-based fallback never ran (got %+v)", res)
	}
}

func TestSilentServiceStillSerialisesTheServiceKey(t *testing.T) {
	// The bridge reads `service`. With `omitempty` an empty string removes the
	// key, so the fallback has to be non-empty for the field to survive NDJSON.
	ln := silentServer(t)
	defer func() { _ = ln.Close() }()

	res := scanSingle(t, ln)
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := decoded["service"]; !present {
		t.Fatalf("`service` missing from %s; the bridge has nothing to report", encoded)
	}
}

func TestBannerServiceOutranksThePortHint(t *testing.T) {
	// An ephemeral port is not a known service, so if the banner were ignored
	// the port hint would answer "tcp". The banner must win.
	ln := newEchoServer(t, "SSH-2.0-OpenSSH_9.6\r\n")
	defer ln.Close()

	res := scanSingle(t, ln)
	if res.Service != "ssh" {
		t.Errorf("service = %q, want ssh (the banner identified it)", res.Service)
	}
	if res.Banner == "" {
		t.Errorf("banner lost: %+v", res)
	}
}

func TestUnrecognisedBannerStillFallsBackToThePortHint(t *testing.T) {
	ln := newEchoServer(t, "some proprietary protocol v3\r\n")
	defer ln.Close()

	res := scanSingle(t, ln)
	if res.Service == "unknown" {
		t.Errorf("service = %q, want the port-based hint", res.Service)
	}
	if res.Service == "" {
		t.Errorf("service empty for a banner that identified nothing: %+v", res)
	}
}

func TestServiceResolutionIsNotConfusedByTheHostPort(t *testing.T) {
	// A banner that is itself pure control bytes sanitises to empty, which is
	// the same state as no banner at all. Both must still reach the port hint.
	ln := newEchoServer(t, "\x00\x01\x02\x03")
	defer ln.Close()

	res := scanSingle(t, ln)
	if res.Banner != "" {
		t.Errorf("banner = %q, want empty", res.Banner)
	}
	if res.Service == "" {
		t.Errorf("service empty; a control-only banner must not suppress the hint")
	}
}
