// HELIOS-NET :: transport/goscan/goscan.go
// High-performance concurrent TCP port scanner written in pure Go.
// Streams results incrementally via NDJSON (Newline Delimited JSON) to prevent pipe buffer deadlocks.

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

type PortResult struct {
	Port int    `json:"port"`
	Open bool   `json:"open"`
	Time string `json:"time"`
}

// Standardized Error Envelope (SEE) — consistent machine-readable error contract.
type ErrorEnvelope struct {
	Status    string `json:"status"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Component string `json:"component"`
	Module    string `json:"module,omitempty"`
}

// emitEnvelope writes a standardized error envelope to stderr as a single line of NDJSON.
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

func scanPort(ip string, port int, timeout time.Duration, wg *sync.WaitGroup, results chan<- PortResult) {
	defer wg.Done()
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err == nil {
		conn.Close()
		results <- PortResult{Port: port, Open: true, Time: time.Now().Format(time.RFC3339)}
	} else {
		results <- PortResult{Port: port, Open: false}
	}
}

func main() {
	if len(os.Args) < 3 {
		emitEnvelope("PARSE_ERROR", "usage: goscan <target-ip> <port1,port2,... or range>", "goscan")
		fmt.Fprintln(os.Stderr, "usage: goscan <target-ip> <port1,port2,... or range>")
		os.Exit(2)
	}

	targetIP := os.Args[1]
	portArg := os.Args[2]

	var ports []int
	p, err := strconv.Atoi(portArg)
	if err == nil {
		ports = []int{p}
	} else {
		ports = []int{21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 5432, 8080}
	}

	var wg sync.WaitGroup
	resultsChan := make(chan PortResult, len(ports))
	timeout := 1500 * time.Millisecond

	for _, p := range ports {
		wg.Add(1)
		go scanPort(targetIP, p, timeout, &wg, resultsChan)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	encoder := json.NewEncoder(os.Stdout)
	for res := range resultsChan {
		if res.Open {
			_ = encoder.Encode(res)
		}
	}
}
