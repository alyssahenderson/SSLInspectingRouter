package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestExtractSNIReturnsReplayBytesWhenSNIAbsent(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientErr := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
		_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		clientErr <- tlsConn.Handshake()
	}()

	handler := &HTTPSHandler{}
	hostname, replay, err := handler.extractSNI(serverConn)
	if !errors.Is(err, errNoSNI) {
		t.Fatalf("extractSNI error = %v, want %v", err, errNoSNI)
	}
	if hostname != "" {
		t.Fatalf("hostname = %q, want empty", hostname)
	}
	if len(replay) == 0 {
		t.Fatal("replay bytes are empty")
	}

	_ = serverConn.Close()
	select {
	case <-clientErr:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for client handshake to finish")
	}
}

func TestDialTunnelTargetUsesSOCKSDialerWhenEnabled(t *testing.T) {
	wantConn := &stubTunnelConn{}
	dialer := &stubSOCKSDialer{
		conn: wantConn,
	}

	h := &HTTPSHandler{
		torDialer: dialer,
	}

	conn, err := h.dialTunnelTarget("example.com:443", time.Second)
	if err != nil {
		t.Fatalf("dialTunnelTarget error = %v", err)
	}
	if conn != wantConn {
		t.Fatalf("conn = %p, want %p", conn, wantConn)
	}
	if !dialer.called {
		t.Fatal("SOCKS dialer was not called")
	}
	if dialer.network != "tcp" {
		t.Fatalf("network = %q, want %q", dialer.network, "tcp")
	}
	if dialer.address != "example.com:443" {
		t.Fatalf("address = %q, want %q", dialer.address, "example.com:443")
	}
}

type stubSOCKSDialer struct {
	called  bool
	network string
	address string
	conn    net.Conn
	err     error
}

func (s *stubSOCKSDialer) Dial(network, address string) (net.Conn, error) {
	s.called = true
	s.network = network
	s.address = address
	if s.err != nil {
		return nil, s.err
	}
	return s.conn, nil
}

type stubTunnelConn struct{}

func (c *stubTunnelConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *stubTunnelConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *stubTunnelConn) Close() error {
	return nil
}

func (c *stubTunnelConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *stubTunnelConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *stubTunnelConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *stubTunnelConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *stubTunnelConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type deadlineRecordingConn struct {
	stubTunnelConn
	mu       sync.Mutex
	deadline time.Time
}

func (c *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = deadline
	return nil
}

func (c *deadlineRecordingConn) currentDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

func TestTunnelActivityRefreshesBothConnectionDeadlines(t *testing.T) {
	clientConn := &deadlineRecordingConn{}
	upstreamConn := &deadlineRecordingConn{}
	activity := &tunnelActivity{
		conns:   []net.Conn{clientConn, upstreamConn},
		timeout: time.Minute,
	}
	upstream := &idleTimeoutConn{Conn: upstreamConn, activity: activity}

	activity.refresh()
	initialClientDeadline := clientConn.currentDeadline()
	initialUpstreamDeadline := upstreamConn.currentDeadline()
	if _, err := upstream.Write([]byte("progress")); err != nil {
		t.Fatalf("upstream Write: %v", err)
	}

	if !clientConn.currentDeadline().After(initialClientDeadline) {
		t.Fatal("activity did not refresh the client connection deadline")
	}
	if !upstreamConn.currentDeadline().After(initialUpstreamDeadline) {
		t.Fatal("activity did not refresh the upstream connection deadline")
	}
}

func TestExtractSNIReadsFragmentedClientHello(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Build a large ClientHello (> 2000 bytes, simulating PQ key shares) with SNI at the end.
	paddingPayload := make([]byte, 2000)
	helloBytes := buildClientHello("pq.example.com", []uint16{0x1301, 0xc02f}, []string{"http/1.1"}, map[uint16][]byte{
		0x0015: paddingPayload,
	})

	go func() {
		// Write the ClientHello across multiple small chunks to simulate TCP segmentation.
		for offset := 0; offset < len(helloBytes); {
			end := offset + 120
			if end > len(helloBytes) {
				end = len(helloBytes)
			}
			_, _ = clientConn.Write(helloBytes[offset:end])
			offset = end
		}
	}()

	handler := &HTTPSHandler{}
	hostname, replay, err := handler.extractSNI(serverConn)
	if err != nil {
		t.Fatalf("extractSNI error = %v, want nil", err)
	}
	if hostname != "pq.example.com" {
		t.Fatalf("hostname = %q, want %q", hostname, "pq.example.com")
	}
	if len(replay) != len(helloBytes) {
		t.Fatalf("len(replay) = %d, want %d", len(replay), len(helloBytes))
	}
}
