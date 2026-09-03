// HELIOS-NET :: transport/rawsocket — نواة الأداء المنخفض (Go)
//
// ترقية جوهرية: إرسال حزمة TCP SYN خام + الاستماع للرد (SYN-ACK / RST)
// للبتّ في حالة المنفذ دون إتمام المصافحة الكاملة (True Stealth SYN Scan).
//
// المخرجات: JSON موحّد يقرؤه المنسّق مباشرة.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type ScanResult struct {
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	State  string `json:"state"` // open | closed | filtered
	Source string `json:"source"`
	Error  string `json:"error,omitempty"`
}

// حساب مجموع التحقق البسيط (Checksum) لرأس TCP/IP (مطلوب لقبول النواة).
func computeChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildSYN(srcIP, dstIP net.IP, sport, dport uint16) []byte {
	packet := make([]byte, 40) // 20 IP + 20 TCP
	// IP Header (IPv4, Header length = 5 words)
	packet[0] = 0x45
	packet[2] = 0x00
	packet[3] = 0x28
	binary.BigEndian.PutUint16(packet[4:], 0x1337) // ID
	binary.BigEndian.PutUint16(packet[6:], 0x4000) // Flags/Fragment
	packet[8] = 64                                 // TTL
	packet[9] = 6                                  // Protocol TCP
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// TCP Header
	binary.BigEndian.PutUint16(packet[20:22], sport)
	binary.BigEndian.PutUint16(packet[22:24], dport)
	binary.BigEndian.PutUint32(packet[24:28], 1000) // Seq
	binary.BigEndian.PutUint32(packet[28:32], 0)   // Ack
	packet[32] = 0x50                              // Data offset (5 words)
	packet[33] = 0x02                              // SYN Flag
	binary.BigEndian.PutUint16(packet[34:36], 1024) // Window
	// Checksum (محسوب مبدئيًا أو مهمل للمختبر البسيط)
	csum := computeChecksum(packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], csum)

	return packet
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: rawsync <dst-ip> <dst-port>")
		os.Exit(2)
	}
	dstIP := net.ParseIP(os.Args[1])
	if dstIP == nil {
		json.NewEncoder(os.Stdout).Encode(ScanResult{State: "filtered", Error: "invalid ip"})
		os.Exit(1)
	}
	var dport uint16
	fmt.Sscanf(os.Args[2], "%d", &dport)
	sport := uint16(49152)

	// استنباط الـ IP المحلي
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(ScanResult{Host: dstIP.String(), Port: dport, State: "filtered", Error: err.Error()})
		os.Exit(1)
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	conn.Close()

	// فتح المقبس الخام للاستماع والإرسال
	sock, err := net.ListenPacket("ip4:tcp", localIP.String())
	if err != nil {
		// إن تعذر فتح المقبس بسبب صلاحيات النظام، نرجع حالة مسجّلة بوضوح
		json.NewEncoder(os.Stdout).Encode(ScanResult{
			Host:   dstIP.String(),
			Port:   dport,
			State:  "filtered",
			Source: "native(Go-raw)",
			Error:  "permission denied or raw socket restricted (" + err.Error() + ")",
		})
		os.Exit(0)
	}
	defer sock.Close()

	packet := buildSYN(localIP, dstIP, sport, dport)
	addr := &net.IPAddr{IP: dstIP}

	if _, err := sock.WriteTo(packet, addr); err != nil {
		json.NewEncoder(os.Stdout).Encode(ScanResult{Host: dstIP.String(), Port: dport, State: "filtered", Error: err.Error()})
		os.Exit(1)
	}

	// ضبط مهلة الاستماع للرد (SYN-ACK أو RST)
	_ = sock.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)

	for {
		n, _, err := sock.ReadFrom(buf)
		if err != nil {
			// إن انتهت المهلة بلا رد = المنفذ محجوب (filtered)
			json.NewEncoder(os.Stdout).Encode(ScanResult{
				Host:   dstIP.String(),
				Port:   dport,
				State:  "filtered",
				Source: "native(Go-raw)",
			})
			return
		}

		if n < 40 {
			continue
		}

		// تحليل رأس IP لمعرفة بدء رأس TCP (طول رأس IP = (buf[0] & 0x0f) * 4)
		ipHeaderLen := int(buf[0]&0x0f) * 4
		if n < ipHeaderLen+20 {
			continue
		}
		tcpHeader := buf[ipHeaderLen:]

		// التحقق من أن الحزمة موجهة للمنفذ المحلي ومصدرها منفذ الهدف
		rPort := binary.BigEndian.Uint16(tcpHeader[0:2])
		lPort := binary.BigEndian.Uint16(tcpHeader[2:4])

		if rPort == dport && lPort == sport {
			flags := tcpHeader[13]
			// SYN-ACK = 0x12 (SYN + ACK)
			if flags&0x12 == 0x12 {
				json.NewEncoder(os.Stdout).Encode(ScanResult{
					Host:   dstIP.String(),
					Port:   dport,
					State:  "open",
					Source: "native(Go-raw)",
				})
				return
			}
			// RST = 0x04 (RST)
			if flags&0x04 == 0x04 {
				json.NewEncoder(os.Stdout).Encode(ScanResult{
					Host:   dstIP.String(),
					Port:   dport,
					State:  "closed",
					Source: "native(Go-raw)",
				})
				return
			}
		}
	}
}
