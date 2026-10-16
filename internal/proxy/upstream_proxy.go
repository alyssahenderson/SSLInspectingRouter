package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
	xproxy "golang.org/x/net/proxy"
)

func newUpstreamTransport(tlsConfig *tls.Config) *http.Transport {
	var tr *http.Transport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok && defaultTransport != nil {
		tr = defaultTransport.Clone()
	} else {
		tr = &http.Transport{}
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	tr.DialContext = dialer.DialContext
	tr.ForceAttemptHTTP2 = false
	tr.MaxIdleConns = 256
	tr.MaxIdleConnsPerHost = 32
	tr.IdleConnTimeout = 90 * time.Second
	tr.TLSHandshakeTimeout = 10 * time.Second
	if tlsConfig != nil {
		tr.TLSClientConfig = tlsConfig
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return tr
}

func readRequestBodyPreview(req *http.Request) ([]byte, io.Reader) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return []byte{}, bytes.NewReader(nil)
	}
	limit := logger.LogBodyLimit()
	if limit <= 0 {
		limit = logger.MaxUntruncatedBytes
	}
	buf, _ := io.ReadAll(io.LimitReader(req.Body, int64(limit)+1))
	if len(buf) <= limit {
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(buf))
		return buf, bytes.NewReader(buf)
	}
	combined := io.MultiReader(bytes.NewReader(buf), req.Body)
	req.Body = io.NopCloser(combined)
	return buf, combined
}

type socksDialer interface {
	Dial(network, address string) (net.Conn, error)
}

func buildSOCKS5RoundTripper(base http.RoundTripper, rawAddr string) (http.RoundTripper, string, error) {
	addr, err := normalizeSOCKS5Address(rawAddr)
	if err != nil {
		return nil, "", err
	}

	proxyURL := &url.URL{
		Scheme: "socks5h",
		Host:   addr,
	}

	if baseTransport, ok := base.(*http.Transport); ok && baseTransport != nil {
		clone := baseTransport.Clone()
		clone.Proxy = http.ProxyURL(proxyURL)
		return clone, addr, nil
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || defaultTransport == nil {
		defaultTransport = &http.Transport{}
	}
	clone := defaultTransport.Clone()
	clone.Proxy = http.ProxyURL(proxyURL)
	return clone, addr, nil
}

func buildSOCKS5Dialer(rawAddr string, timeout time.Duration) (socksDialer, string, error) {
	addr, err := normalizeSOCKS5Address(rawAddr)
	if err != nil {
		return nil, "", err
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	netDialer := &net.Dialer{
		Timeout: timeout,
	}
	dialer, err := xproxy.SOCKS5("tcp", addr, nil, netDialer)
	if err != nil {
		return nil, "", fmt.Errorf("failed to initialize SOCKS5 dialer for %s: %w", addr, err)
	}
	return dialer, addr, nil
}

func normalizeSOCKS5Address(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("SOCKS address cannot be empty")
	}

	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("invalid SOCKS address %q", raw)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("invalid SOCKS address %q", raw)
	}
	if _, err := net.LookupPort("tcp", strings.TrimSpace(port)); err != nil {
		return "", fmt.Errorf("invalid SOCKS address %q", raw)
	}

	return net.JoinHostPort(host, port), nil
}
