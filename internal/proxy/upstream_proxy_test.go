package proxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

func TestNewUpstreamTransportDisablesHTTP2(t *testing.T) {
	if transport := newUpstreamTransport(nil); transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = true, want false")
	}
}

func TestReadRequestBodyPreviewKeepsTruncationSentinelAndFullReplay(t *testing.T) {
	limit := logger.LogBodyLimit()
	body := strings.Repeat("x", limit+5)
	req := httptest.NewRequest("POST", "http://example.com", strings.NewReader(body))

	preview, upstreamBody := readRequestBodyPreview(req)
	if len(preview) != limit+1 {
		t.Fatalf("preview length = %d, want %d", len(preview), limit+1)
	}
	replayed, err := io.ReadAll(upstreamBody)
	if err != nil {
		t.Fatalf("reading replay body: %v", err)
	}
	if !bytes.Equal(replayed, []byte(body)) {
		t.Fatalf("replayed body length = %d, want %d", len(replayed), len(body))
	}
}

func TestNormalizeSOCKS5Address(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "ipv4",
			input: "127.0.0.1:9050",
			want:  "127.0.0.1:9050",
		},
		{
			name:  "ipv6",
			input: "[::1]:9050",
			want:  "[::1]:9050",
		},
		{
			name:    "missing port",
			input:   "127.0.0.1",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeSOCKS5Address(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (value=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildSOCKS5Dialer(t *testing.T) {
	dialer, addr, err := buildSOCKS5Dialer("127.0.0.1:9050", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer == nil {
		t.Fatal("dialer is nil")
	}
	if addr != "127.0.0.1:9050" {
		t.Fatalf("address = %q, want %q", addr, "127.0.0.1:9050")
	}
}
