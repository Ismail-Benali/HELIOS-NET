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

// grabBanner attempts to read a greeting banner from an open TCP connection with a strict timeout.
func grabBanner(conn net.Conn) (string, string) {
	_ = conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	reader := bufio.NewReader(conn)
	
	// Check if service sends data first (like SSH, FTP, SMTP)
	buf := make([]byte, 256)
	n, err := reader.Read(buf)
	if err == nil && n > 0 {
		raw := string(buf[:n])
		cleaned := strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 {
				return r
			}
			return ' '
		}, raw)
		cleaned = strings.TrimSpace(cleaned)
		
		svc := guessServiceFromBanner(cleaned)
		return cleaned, svc
	}
	return "", ""
}

func guessServiceFromBanner(banner string) string {
	lower := strings.ToLower(banner)
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
	if strings.Contains(lower, "mysql") {
		return "mysql"
	}
	if strings.Contains(lower, "redis") {
		return "redis"
	}
	return "unknown"
}

func scanPort(ip string, port int, timeout time.Duration, sem chan struct{}, wg *sync.WaitGroup, results chan<- PortResult) {
	defer wg.Done()
	<-sem // acquire token
	defer func() { sem <- struct{}() }() // release token

	target := fmt.Sprintf("%s:%d", ip, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	latency := time.Since(start).Milliseconds()

	if err == nil {
		defer conn.Close()
		banner, service := grabBanner(conn)
		if service == "unknown" {
			// fallback port-based hint
			service = guessServiceFromPort(port)
		}
		results <- PortResult{
			Port:      port,
			Open:      true,
			Banner:    banner,
			Service:   service,
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

func parsePorts(arg string) []int {
	var ports []int
	if strings.Contains(arg, ",") {
		parts := strings.Split(arg, ",")
		for _, p := range parts {
			if val, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				ports = append(ports, val)
			}
		}
	} else if strings.Contains(arg, "-") {
		parts := strings.Split(arg, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && start <= end {
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		}
	} else if val, err := strconv.Atoi(arg); err == nil {
		ports = []int{val}
	} else {
		// Default top common ports
		ports = []int{21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 5432, 8080}
	}
	return ports
}

func main() {
	if len(os.Args) < 3 {
		emitEnvelope("PARSE_ERROR", "usage: goscan <target-ip> <ports: 80 or 1-1000 or 80,443>", "goscan")
		fmt.Fprintln(os.Stderr, "usage: goscan <target-ip> <port>")
		os.Exit(2)
	}

	targetIP := os.Args[1]
	portArg := os.Args[2]
	ports := parsePorts(portArg)

	// Bounded worker pool (Semaphore) to control concurrency and avoid flooding / fd exhaustion
	maxWorkers := 300
	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup
	resultsChan := make(chan PortResult, len(ports))
	timeout := 1200 * time.Millisecond

	for _, p := range ports {
		wg.Add(1)
		go scanPort(targetIP, p, timeout, sem, &wg, resultsChan)
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
