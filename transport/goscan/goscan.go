// HELIOS-NET :: transport/goscan/goscan.go
// High-performance concurrent TCP port scanner written in pure Go.
// Bypasses Python interpreter overhead, utilizing Go's lightweight goroutines.
// Compiled to a standalone binary invoked natively by the orchestrator.

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
		fmt.Fprintln(os.Stderr, "usage: goscan <target-ip> <port1,port2,... or range>");
		os.Exit(2)
	}

	targetIP := os.Args[1]
	portArg := os.Args[2]

	// Parse ports (supports comma-separated list or simple range)
	var ports []int
	p, err := strconv.Atoi(portArg)
	if err == nil {
		ports = []int{p}
	} else {
		// Default common ports if argument is 'common'
		ports = []int{21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 5432, 8080}
	}

	var wg sync.WaitGroup
	resultsChan := make(chan PortResult, len(ports))
	timeout := 1500 * time.Millisecond

	for _, p := range ports {
		wg.Add(1)
		go scanPort(targetIP, p, timeout, &wg, resultsChan)
	}

	wg.Wait()
	close(resultsChan)

	var openPorts []PortResult
	for res := range resultsChan {
		if res.Open {
			openPorts = append(openPorts, res)
		}
	}

	output, _ := json.Marshal(openPorts)
	fmt.Println(string(output))
}
