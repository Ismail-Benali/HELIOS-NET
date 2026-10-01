// Regression tests for defects found by the fuzz targets in fuzz_test.go.
//
// These are kept as ordinary named tests rather than only as corpus files, so
// `go test` fails loudly if either defect is ever reintroduced.

package main

import "testing"

// TestParsePortsRemovesDuplicates covers the input the fuzzer found:
// parsePorts("1,1 ") returned port 1 twice, so an operator writing "80,80,443"
// had the same port scanned and reported more than once, inflating the
// open-port count in the report. Overlapping ranges in a comma list are covered
// by TestParsePortsAcceptsRangesInsideCommaLists below.
func TestParsePortsRemovesDuplicates(t *testing.T) {
	cases := []struct {
		arg  string
		want []int
	}{
		{"1,1", []int{1}},
		{"1,1 ", []int{1}},
		{"80,80,443", []int{80, 443}},
		{"443,80,443,80", []int{443, 80}},
		{"22,22,22,22", []int{22}},
		{" 80 , 80 ", []int{80}},
	}
	for _, tc := range cases {
		got := parsePorts(tc.arg)
		if len(got) != len(tc.want) {
			t.Fatalf("parsePorts(%q) = %v, want %v", tc.arg, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("parsePorts(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		}
	}
}

// TestParsePortsAcceptsRangesInsideCommaLists covers a gap that the duplicate
// test above only described in a comment: the comma branch accepted bare
// integers and silently dropped range tokens. "1-100,50-200" produced an empty
// list, fell through to defaultPorts(), and returned 13 common ports for what
// reads as a 200-port sweep, with no error.
func TestParsePortsAcceptsRangesInsideCommaLists(t *testing.T) {
	cases := []struct {
		arg  string
		want []int
	}{
		// Overlapping ranges collapse to their union, in first-seen order.
		{"1-100,50-200", rangePorts(1, 200)},
		{"22,1-3,2", []int{22, 1, 2, 3}},
		{"1-3,22", []int{1, 2, 3, 22}},
		{" 1 - 2 , 3 ", []int{1, 2, 3}},
		// A malformed token is skipped, the valid ones still apply. This is the
		// partial-acceptance behaviour the single-value form already had.
		{"1-3,not-a-port,5", []int{1, 2, 3, 5}},
		// A reversed range is a typo, not a request to wrap around, and it
		// yields no ports rather than falling back to the default list.
		{"100-1", nil},
		// Every token invalid falls back, which is the long-standing contract.
		{"nope,also-nope", defaultPorts()},
	}
	for _, tc := range cases {
		got := parsePorts(tc.arg)
		if len(got) != len(tc.want) {
			t.Fatalf("parsePorts(%q) = %v, want %v", tc.arg, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("parsePorts(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		}
	}
}

func rangePorts(start, end int) []int {
	var out []int
	for i := start; i <= end; i++ {
		out = append(out, i)
	}
	return out
}

// TestParsePortsClampsHugeRanges pins a defect the fuzzer found after the range
// support was added. Sizing the slice from the raw request made "1-999999999"
// reserve a billion-element capacity, about 8 GB of address space, and then loop
// a billion times to keep the 65535 valid ports. The 64-bit allocator reserves
// rather than faults, so it looked like it worked while burning seconds of CPU
// on every scan, and it would have failed outright on a memory-limited runner.
func TestParsePortsClampsHugeRanges(t *testing.T) {
	cases := []struct {
		arg  string
		want int
	}{
		{"1-999999999", 65535},
		{"1-2000000000", 65535},
		{"1-65536", 65535},
		{"1-10", 10},
		// Entirely outside the valid port space, so no ports and no fallback.
		{"70000-80000", 0},
		// A leading minus is not a range spec: the split yields more than two
		// fields, so this is malformed input and falls back, as before.
		{"-5000000-70000", len(defaultPorts())},
		{"-100--50", len(defaultPorts())},
	}
	for _, tc := range cases {
		got := parsePorts(tc.arg)
		if len(got) != tc.want {
			t.Fatalf("parsePorts(%q) returned %d ports, want %d", tc.arg, len(got), tc.want)
		}
		for i, p := range got {
			if !validPort(p) {
				t.Fatalf("parsePorts(%q)[%d] = %d is not a valid port", tc.arg, i, p)
			}
		}
	}
}

// TestParsePortsNamedPresets pins the two documented presets. "all" used to
// fall through to the default branch and quietly scan 13 ports, so
// `goscan host all` reported a successful but badly incomplete sweep.
func TestParsePortsNamedPresets(t *testing.T) {
	common := parsePorts("common")
	if len(common) != len(defaultPorts()) {
		t.Fatalf("common = %d ports, want %d", len(common), len(defaultPorts()))
	}
	for _, arg := range []string{"all", "ALL", "Full", "1-65535"} {
		got := parsePorts(arg)
		if len(got) != 65535 {
			t.Fatalf("parsePorts(%q) = %d ports, want 65535", arg, len(got))
		}
		if got[0] != 1 || got[len(got)-1] != 65535 {
			t.Fatalf("parsePorts(%q) does not span 1..65535: %d..%d",
				arg, got[0], got[len(got)-1])
		}
	}
}
