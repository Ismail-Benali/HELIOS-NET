// Fuzz and benchmark coverage for the Go scanner.
//
// Fuzzing is built into the Go toolchain (1.18+), so these targets need no
// external dependency and no network access: parsePorts, sanitizeBanner,
// guessServiceFromBanner and the JSON encoder all take untrusted bytes, either
// from a command-line argument or from a banner returned by a remote host.
//
// Invariants asserted here are the ones a crash or a malformed record would
// break. A banner is fully attacker-controlled, so sanitising it and encoding
// it are the two places a hostile peer could reach the rest of the pipeline.

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- fuzzing

func FuzzParsePorts(f *testing.F) {
	// Seeds cover the shapes seen in practice plus the ones that used to break:
	// the "Heilig dash" form, garbage, and out-of-range values.
	for _, s := range []string{
		"", " ", "80", "common", "all", "1-100", "22,80,443",
		"not-a-port", "80,not-a-port,443", "0", "65535", "65536", "70000",
		"100-1", "-1", "1-", "1--5", "1-2-3", ",,,", "80,", ",80",
		"1 - 5", "1\t2", "0x50", "1e3", "+80", "80.0", "\u0668\u0660",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, arg string) {
		ports := parsePorts(arg)

		// Every returned port must be connectable. Returning 0 or a negative
		// port would silently produce a useless scan.
		for _, p := range ports {
			if !validPort(p) {
				t.Fatalf("parsePorts(%q) returned out-of-range port %d", arg, p)
			}
		}

		// No duplicates: a repeated port would be scanned twice and reported
		// twice, inflating the result set.
		seen := make(map[int]bool, len(ports))
		for _, p := range ports {
			if seen[p] {
				t.Fatalf("parsePorts(%q) returned duplicate port %d", arg, p)
			}
			seen[p] = true
		}

		// An entirely blank argument must not explode into a full sweep; that
		// is how a typo turns into a 65535-port scan against a target.
		if strings.TrimSpace(arg) == "" && len(ports) != len(defaultPorts()) {
			t.Fatalf("parsePorts(%q) returned %d ports, want the default set",
				arg, len(ports))
		}
	})
}

func FuzzSanitizeBanner(f *testing.F) {
	for _, s := range []string{
		"", "SSH-2.0-OpenSSH_9.6", "220 ProFTPD 1.3.5 Server ready",
		"\x00\x01\x02", "\x7f\x80\xff", "line one\nline two\r\n",
		strings.Repeat("A", 5000), "\t\t\t", "\x00\x01\x02",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got := sanitizeBanner(raw)

		// Length is capped so a hostile peer cannot inflate one result record.
		if len(got) > bannerLimit {
			t.Fatalf("sanitizeBanner returned %d bytes, cap is %d", len(got), bannerLimit)
		}

		// No control bytes may survive: NDJSON is line-delimited, so an
		// embedded newline would let a remote host forge extra result lines.
		for i := 0; i < len(got); i++ {
			c := got[i]
			if c < 0x20 || c == 0x7f {
				t.Fatalf("sanitizeBanner(%q) kept control byte 0x%02x at %d", raw, c, i)
			}
		}

		// The sanitised banner must still be JSON-encodable on one line.
		encoded, err := json.Marshal(PortResult{Banner: got})
		if err != nil {
			t.Fatalf("sanitizeBanner output is not encodable: %v", err)
		}
		if strings.ContainsAny(string(encoded), "\n\r") {
			t.Fatalf("encoded banner contains a line break: %q", encoded)
		}
	})
}

func FuzzGuessServiceFromBanner(f *testing.F) {
	for _, s := range []string{
		"", "SSH-2.0-OpenSSH_9.6", "220 ProFTPD ready", "HTTP/1.1 200 OK",
		"\x00mysql", "mariadb", "POSTGRES", "smtp", "IMAP", "pop3", "telnet",
		"random noise with no service marker at all",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, banner string) {
		// The detector may be wrong about a service, but it must never invent
		// a name containing a quote or a backslash, which would break the JSON
		// record that carries it.
		svc := guessServiceFromBanner(banner)
		if svc == "" {
			return
		}
		if strings.ContainsAny(svc, "\"\\\n\r\t") {
			t.Fatalf("service name %q is not safe for a JSON record", svc)
		}
	})
}

// FuzzResolveService pins the invariant that made the silent-service defect
// possible in the first place: whatever the peer said, or did not say, the
// service field is never empty. An empty string is not a harmless default --
// Service is `omitempty`, so it deletes the key from the NDJSON and the Python
// bridge reports nothing at all about a port that was proven open.
func FuzzResolveService(f *testing.F) {
	for _, c := range []struct {
		banner string
		port   int
	}{
		{"", 80}, {"", 65535}, {"", 1}, {"", -1}, {"", 0}, {"", 1 << 30},
		{"unknown", 443}, {"", 70000}, {"ssh", 65000}, {"\x00\x01", 22},
		{"unknown", -5}, {"  ", 8080},
	} {
		f.Add(c.banner, c.port)
	}

	f.Fuzz(func(t *testing.T, bannerService string, port int) {
		got := resolveService(bannerService, port)

		if got == "" {
			t.Fatalf("resolveService(%q, %d) = %q; omitempty would drop the key",
				bannerService, port, got)
		}

		// The name travels inside a JSON record, so it must stay on one line and
		// must not be able to break out of the string.
		if strings.ContainsAny(got, "\"\\\n\r\t") {
			t.Fatalf("service name %q is not safe for a JSON record", got)
		}

		// A recognised service name must be preserved verbatim; the port hint is
		// a fallback, not an override. Anything the detectors never emit is not a
		// name at all and must be discarded, so a raw banner cannot reach the
		// field a consumer reads as a service name.
		if knownServices[bannerService] {
			if got != bannerService {
				t.Fatalf("resolveService(%q, %d) = %q; a known name was overridden",
					bannerService, port, got)
			}
		} else if got != guessServiceFromPort(port) {
			t.Fatalf("resolveService(%q, %d) = %q; unrecognised input must fall "+
				"back to the port hint %q", bannerService, port, got, guessServiceFromPort(port))
		}

		// The encoded record must carry the key, which is the whole point.
		raw, err := json.Marshal(PortResult{Port: port, Open: true, Service: got})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, present := decoded["service"]; !present {
			t.Fatalf("`service` missing from %s", raw)
		}
	})
}

// FuzzPortResultJSON checks that every record the core can emit survives a
// JSON round trip. A result that cannot be encoded would be dropped by the
// Python bridge, turning a real finding into silence.
func FuzzPortResultJSON(f *testing.F) {
	f.Add(1, true, "ssh", "SSH-2.0-OpenSSH", int64(12), "2026-01-01T00:00:00Z")
	f.Add(65535, true, "", "", int64(0), "")
	f.Add(0, false, "", "", int64(-1), "")

	f.Fuzz(func(t *testing.T, port int, open bool, svc, banner string, ms int64, ts string) {
		r := PortResult{
			Port:      port,
			Open:      open,
			Service:   svc,
			Banner:    banner,
			LatencyMs: ms,
			Time:      ts,
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("PortResult does not encode: %v", err)
		}
		if strings.ContainsAny(string(raw), "\n\r") {
			t.Fatalf("PortResult encodes to more than one line: %q", raw)
		}
		var back PortResult
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("PortResult does not round trip: %v", err)
		}
		if back.Port != port || back.Open != open {
			t.Fatalf("round trip changed port/open: %d/%v", back.Port, back.Open)
		}
	})
}

// ------------------------------------------------------------- benchmarks

func BenchmarkParsePortsCommon(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if got := parsePorts("common"); len(got) == 0 {
			b.Fatal("common resolved to no ports")
		}
	}
}

func BenchmarkParsePortsRange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if got := parsePorts("1-1024"); len(got) != 1024 {
			b.Fatalf("range resolved to %d ports", len(got))
		}
	}
}

func BenchmarkParsePortsAll(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if got := parsePorts("all"); len(got) != 65535 {
			b.Fatalf("all resolved to %d ports", len(got))
		}
	}
}

// BenchmarkDedupePorts measures the dedupe pass that the fuzzer forced into the
// scanner. It runs once per argument, so a large overlapping range pays for it.
func BenchmarkDedupePorts(b *testing.B) {
	ports := make([]int, 0, 65535)
	for i := 1; i <= 65535; i++ {
		ports = append(ports, i, i) // every port duplicated
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := dedupePorts(ports); len(got) != 65535 {
			b.Fatalf("dedupe returned %d", len(got))
		}
	}
}

func BenchmarkSanitizeBanner(b *testing.B) {
	raw := strings.Repeat("SSH-2.0-OpenSSH_9.6 ", 40)
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeBanner(raw)
	}
}

func BenchmarkSanitizeBannerHostile(b *testing.B) {
	raw := strings.Repeat("\x00\x1b[31m", 200)
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeBanner(raw)
	}
}

func BenchmarkGuessServiceFromBanner(b *testing.B) {
	raw := "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.1]"
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = guessServiceFromBanner(raw)
	}
}

func BenchmarkMaxWorkersFor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = maxWorkersFor(65535)
	}
}

// BenchmarkStartScanClosedPorts measures the scanner against a port that is
// guaranteed closed, which is the common case in a real sweep and the case
// that dominated the original deadlock.
func BenchmarkStartScanClosedPorts(b *testing.B) {
	for i := 0; i < b.N; i++ {
		results, done := startScan("127.0.0.1", []int{1}, 200*time.Millisecond)
		for range results {
		}
		done()
	}
}
