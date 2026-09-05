package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/policy"
)

func upstreamClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           publicDial,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 45 * time.Second,
			IdleConnTimeout:       60 * time.Second,
			MaxIdleConns:          64, MaxIdleConnsPerHost: 16, MaxConnsPerHost: 32,
			MaxResponseHeaderBytes: 32 << 10,
			DisableCompression:     true, ForceAttemptHTTP2: true,
		},
	}
}

func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || !policy.HostAllowed(host) {
		return nil, errors.New("destination denied")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("DNS unavailable")
	}
	for _, ip := range ips {
		if !policy.PublicIP(ip) {
			return nil, errors.New("destination denied")
		}
	}
	for _, ip := range ips {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(netip.Addr(ip).String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("upstream unavailable")
}
