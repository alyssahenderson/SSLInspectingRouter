package pcap

import (
	"crypto/md5"
	"math/rand"
	"net"
	"strconv"
	"sync"
)

var (
	GlobalManager *Manager
	dummyMAC      = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	routerMAC     = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

type Manager struct {
	writer *Writer
	mu     sync.Mutex
	flows  map[int64]*Flow // Map RequestID to Flow
}

type Flow struct {
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
	Seq     uint32
	Ack     uint32
}

func Init(filename string) error {
	w, err := NewWriter(filename)
	if err != nil {
		return err
	}
	GlobalManager = &Manager{
		writer: w,
		flows:  make(map[int64]*Flow),
	}
	return nil
}

func Close() {
	if GlobalManager != nil && GlobalManager.writer != nil {
		GlobalManager.writer.Close()
	}
}

// Map FQDN to a consistent fake IP (10.200.x.x)
func resolveFakeIP(fqdn string) net.IP {
	hash := md5.Sum([]byte(fqdn))
	// Use 2nd and 3rd bytes of hash for x.y
	return net.IPv4(10, 200, hash[1], hash[2])
}

const (
	maxSegmentSize = 1460
	maxActiveFlows = 10000
)

func (m *Manager) GetOrCreateFlow(reqID int64, srcIPStr, fqdn string) *Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getOrCreateFlowLocked(reqID, srcIPStr, fqdn)
}

func (m *Manager) getOrCreateFlowLocked(reqID int64, srcIPStr, fqdn string) *Flow {
	if flow, ok := m.flows[reqID]; ok {
		return flow
	}

	if len(m.flows) >= maxActiveFlows {
		for id := range m.flows {
			delete(m.flows, id)
			break
		}
	}

	srcIP := net.ParseIP(srcIPStr)
	if srcIP == nil {
		srcIP = net.IPv4(192, 168, 1, 100) // Fallback
	}

	// Fake random source port for entropy if we can't get real one
	srcPort := 50000 + (int(reqID) % 10000)

	flow := &Flow{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   resolveFakeIP(fqdn),
		DstPort: 443, // Assuming HTTPS primarily
		Seq:     rand.Uint32(),
		Ack:     rand.Uint32(),
	}
	m.flows[reqID] = flow
	return flow
}

func (m *Manager) WriteRequest(reqID int64, srcIPStr, fqdn string, body []byte) {
	if m == nil {
		return
	}

	m.mu.Lock()
	flow := m.getOrCreateFlowLocked(reqID, srcIPStr, fqdn)
	srcIP := flow.SrcIP
	dstIP := flow.DstIP
	srcPort := flow.SrcPort
	dstPort := flow.DstPort
	seq := flow.Seq
	ack := flow.Ack
	flow.Seq += uint32(len(body))
	m.mu.Unlock()

	m.writeSegmented(srcIP, dstIP, srcPort, dstPort, seq, ack, body)
}

func (m *Manager) WriteResponse(reqID int64, srcIPStr, fqdn string, body []byte) {
	if m == nil {
		return
	}

	m.mu.Lock()
	flow, ok := m.flows[reqID]
	if !ok {
		flow = m.getOrCreateFlowLocked(reqID, srcIPStr, fqdn)
	}
	srcIP := flow.DstIP
	dstIP := flow.SrcIP
	srcPort := flow.DstPort
	dstPort := flow.SrcPort
	seq := flow.Ack
	ack := flow.Seq
	flow.Ack += uint32(len(body))
	delete(m.flows, reqID)
	m.mu.Unlock()

	m.writeSegmented(srcIP, dstIP, srcPort, dstPort, seq, ack, body)
}

func (m *Manager) writeSegmented(srcIP, dstIP net.IP, srcPort, dstPort int, seq, ack uint32, body []byte) {
	if len(body) == 0 {
		pkt := m.buildPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, 0x18, body)
		_ = m.writer.WritePacket(pkt)
		return
	}

	numSegments := (len(body) + maxSegmentSize - 1) / maxSegmentSize
	packets := make([][]byte, 0, numSegments)
	for offset := 0; offset < len(body); offset += maxSegmentSize {
		end := offset + maxSegmentSize
		flags := byte(0x10) // ACK
		if end >= len(body) {
			end = len(body)
			flags = 0x18 // PSH|ACK on final segment
		}
		chunk := body[offset:end]
		pkt := m.buildPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, chunk)
		packets = append(packets, pkt)
		seq += uint32(len(chunk))
	}
	_ = m.writer.WritePackets(packets)
}

func (m *Manager) buildPacket(src, dst net.IP, srcPort, dstPort int, seq, ack uint32, flags byte, payload []byte) []byte {
	eth := BuildEthernetHeader(dummyMAC, routerMAC)
	ip := BuildIPv4Header(src, dst, 20+len(payload), 1234)
	tcp := BuildTCPHeader(srcPort, dstPort, seq, ack, flags, 65535, payload, src, dst)

	full := append(eth, ip...)
	full = append(full, tcp...)
	full = append(full, payload...)
	return full
}

// Utility to parse port from IP string if present
func parsePort(s string) int {
	_, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(portStr)
	return p
}
