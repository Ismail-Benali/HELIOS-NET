package main

import (
	"runtime"
	"testing"
	"time"
)

// A full sweep used to spawn one goroutine per port and let all but maxWorkers
// of them park on a counting semaphore:
//
//	PORTS=65535 PEAK_GOROUTINES=55252 MAXWORKERS=300
//
// The semaphore capped concurrent dials, not goroutines, so a wide sweep cost
// tens of megabytes of stacks to run three hundred connections. The bound has
// to be observable as a property of the scheduler, otherwise the memory cost
// quietly returns with any refactor that reintroduces per-port goroutines.

// sweepSize is comfortably above maxWorkers so that a per-port fan-out is
// unmistakable, while a correctly bounded pool stays at the pool size.
const sweepSize = 20000

// goroutineSlack covers the machinery the scan legitimately needs: the closer
// goroutine, the sampler, the Go runtime itself, and test scaffolding.
const goroutineSlack = 250

func measureSweepPeakGoroutines(t *testing.T) int {
	t.Helper()

	baseline := runtime.NumGoroutine()
	ports := make([]int, sweepSize)
	for i := range ports {
		// 127.0.0.1 with a closed port: the dial fails fast, so the workers are
		// never blocked on the network and the measurement stays about the
		// scheduler rather than about dial latency.
		ports[i] = 1
	}

	results, wait := startScan("127.0.0.1", ports, 50*time.Millisecond)

	peak := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := runtime.NumGoroutine() - baseline; n > peak {
			peak = n
		}
		select {
		case _, ok := <-results:
			if !ok {
				// Stream closed; drain finished.
				wait()
				return peak
			}
		default:
		}
	}

	// Timed out still draining. Close the loop rather than leaking the workers.
	for range results {
	}
	wait()
	return peak
}

func TestWideSweepDoesNotSpawnAGoroutinePerPort(t *testing.T) {
	peak := measureSweepPeakGoroutines(t)
	budget := maxWorkersFor(sweepSize) + goroutineSlack

	if peak > budget {
		t.Fatalf("wide sweep peaked at %d goroutines for %d ports; the scheduler "+
			"must not spawn one goroutine per port (budget %d = maxWorkers %d + slack %d)",
			peak, sweepSize, budget, maxWorkersFor(sweepSize), goroutineSlack)
	}
	t.Logf("peak goroutines for a %d-port sweep: %d (budget %d)", sweepSize, peak, budget)
}

func TestWideSweepStaysBoundedAcrossRuns(t *testing.T) {
	// A single sample can be caught mid-ramp. The bound has to hold every time,
	// so repeat it: one run over budget means the fan-out is back.
	for run := 0; run < 3; run++ {
		peak := measureSweepPeakGoroutines(t)
		if budget := maxWorkersFor(sweepSize) + goroutineSlack; peak > budget {
			t.Fatalf("run %d: peak %d goroutines exceeds budget %d", run, peak, budget)
		}
	}
}

func TestEveryPortInAWideSweepStillGetsExactlyOneResult(t *testing.T) {
	// The bound is only legitimate if nothing is dropped. A pool that stops early
	// would also keep the goroutine count flat while silently skipping ports,
	// which is the failure mode a naive fix to this defect would introduce.
	//
	// The ports have to be distinct. Repeating one port cannot show a dropped
	// port, because results are counted by port number and there is then only
	// one candidate: this used to request 2000 copies of port 1 and then
	// assert 2000 distinct ports, which no correct implementation could satisfy.
	const requested = 2000
	ports := make([]int, requested)
	for i := range ports {
		ports[i] = 20000 + i
	}
	results, wait := startScan("127.0.0.1", ports, 20*time.Millisecond)

	seen := make(map[int]int, requested)
	for res := range results {
		seen[res.Port]++
	}
	wait()

	if len(seen) != requested {
		t.Fatalf("got %d distinct ports, want %d", len(seen), requested)
	}
	for i, port := range ports {
		if seen[port] != 1 {
			t.Fatalf("port %d (index %d) reported %d times, want exactly 1",
				port, i, seen[port])
		}
	}
}

func TestEmptySweepTerminatesAndClosesTheStream(t *testing.T) {
	// Zero ports means zero workers. The stream must still be closed, otherwise a
	// consumer ranging over it waits forever.
	results, wait := startScan("127.0.0.1", nil, 50*time.Millisecond)

	done := make(chan struct{})
	go func() {
		for range results {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("empty sweep never closed its result stream")
	}
	wait()
}

func TestNarrowSweepDoesNotUnderFillThePool(t *testing.T) {
	// maxWorkersFor exists so a small sweep is not throttled to nothing. The
	// bounded scheduler must keep that property, or a one-port scan would run on
	// a pool of zero workers.
	ports := []int{1, 2, 3}
	results, wait := startScan("127.0.0.1", ports, 50*time.Millisecond)

	count := 0
	for range results {
		count++
	}
	wait()

	if count != len(ports) {
		t.Fatalf("narrow sweep reported %d results, want %d", count, len(ports))
	}
}
