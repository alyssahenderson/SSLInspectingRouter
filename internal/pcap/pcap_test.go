package pcap_test

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/pcap"
)

func TestPcapGeneration(t *testing.T) {
	tmpfile := "test_output.pcap"
	defer os.Remove(tmpfile)

	// Determine file size before init
	// It should be 0 or not exist

	err := pcap.Init(tmpfile)
	if err != nil {
		t.Fatalf("Failed to init pcap: %v", err)
	}

	// Write a dummy request
	pcap.GlobalManager.WriteRequest(1, "192.168.1.10", "example.com", []byte("GET / HTTP/1.1\r\n\r\n"))

	// Write a dummy response
	pcap.GlobalManager.WriteResponse(1, "192.168.1.10", "example.com", []byte("HTTP/1.1 200 OK\r\n\r\nHello"))

	pcap.Close()

	// Verify file exists and has content
	content, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read pcap file: %v", err)
	}

	if len(content) < 24 {
		t.Fatalf("File too small to contain global header: %d bytes", len(content))
	}

	// Check Magic Number (0xa1b2c3d4 in Little Endian)
	magic := binary.LittleEndian.Uint32(content[0:4])
	if magic != 0xa1b2c3d4 {
		t.Fatalf("Invalid magic number: expected 0xa1b2c3d4, got 0x%x", magic)
	}

	t.Logf("PCAP file generated successfully, size: %d bytes", len(content))
}

func TestPcapLargePayloadSegmentation(t *testing.T) {
	tmpfile := "test_large_output.pcap"
	defer os.Remove(tmpfile)

	if err := pcap.Init(tmpfile); err != nil {
		t.Fatalf("Failed to init pcap: %v", err)
	}

	largeBody := make([]byte, 70000)
	for i := range largeBody {
		largeBody[i] = byte('A' + (i % 26))
	}

	pcap.GlobalManager.WriteRequest(42, "192.168.1.10", "example.com", []byte("GET /large HTTP/1.1\r\n\r\n"))
	pcap.GlobalManager.WriteResponse(42, "192.168.1.10", "example.com", largeBody)
	pcap.Close()

	content, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read pcap file: %v", err)
	}
	if len(content) < 24 {
		t.Fatalf("PCAP file too small: %d", len(content))
	}

	// Walk all packets in the PCAP file and verify incl_len <= 1514 (14 eth + 20 ip + 20 tcp + 1460 mss)
	offset := 24
	packetCount := 0
	totalPayloadBytes := 0
	for offset+16 <= len(content) {
		inclLen := int(binary.LittleEndian.Uint32(content[offset+8 : offset+12]))
		origLen := int(binary.LittleEndian.Uint32(content[offset+12 : offset+16]))
		if inclLen != origLen {
			t.Fatalf("packet %d inclLen=%d != origLen=%d", packetCount, inclLen, origLen)
		}
		if inclLen > 1514 || inclLen < 54 {
			t.Fatalf("packet %d unexpected frame length %d", packetCount, inclLen)
		}
		offset += 16
		if offset+inclLen > len(content) {
			t.Fatalf("packet %d truncated at offset %d", packetCount, offset)
		}
		ipTotalLen := int(binary.BigEndian.Uint16(content[offset+14+2 : offset+14+4]))
		if ipTotalLen != inclLen-14 {
			t.Fatalf("packet %d IP total length %d != %d", packetCount, ipTotalLen, inclLen-14)
		}
		totalPayloadBytes += inclLen - 54
		offset += inclLen
		packetCount++
	}
	if offset != len(content) {
		t.Fatalf("trailing bytes in PCAP: offset=%d len=%d", offset, len(content))
	}
	wantPayload := len("GET /large HTTP/1.1\r\n\r\n") + len(largeBody)
	if totalPayloadBytes != wantPayload {
		t.Fatalf("total TCP payload = %d, want %d", totalPayloadBytes, wantPayload)
	}
}
