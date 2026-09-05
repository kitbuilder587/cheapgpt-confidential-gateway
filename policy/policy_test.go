package policy

import (
	"net/netip"
	"testing"
)

func TestDestinations(t *testing.T) {
	tests := []struct {
		host, path string
		allowed    bool
	}{
		{"chatgpt.com", "/backend-api/codex/responses", true},
		{"api.anthropic.com", "/v1/messages?beta=true", true},
		{"api.anthropic.com", "/v1/messages", true},
		{"daily-cloudcode-pa.googleapis.com", "/v1internal:streamGenerateContent?alt=sse", true},
		{"openrouter.ai", "/api/v1/responses", true},
		{"openrouter.ai", "/api/v1/chat/completions", true},
		{"openrouter.ai", "/api/v1/completions", true},
		{"ai-gateway.vercel.sh", "/v1/messages/count_tokens", true},
		{"runtime.us-east-1.kiro.dev", "/example-operation", true},
		{"runtime.us-east-1.kiro.dev", "/", true},
		{"runtime.us-east-1.kiro.dev.evil.test", "/", false},
		{"runtime.eu-central-1.kiro.dev", "/", false},
		{"api.anthropic.com:443", "/v1/messages", false},
		{"API.ANTHROPIC.COM", "/v1/messages", false},
		{"api.anthropic.com", "/v1/messages?beta=true&beta=false", false},
		{"api.anthropic.com", "/v1/messages?redirect=https://evil.test", false},
		{"api.anthropic.com", "/v1/messages?beta=%74rue", false},
		{"api.anthropic.com", "/v1/messages/", false},
		{"runtime.us-east-1.kiro.dev", "//evil.test/path", false},
		{"runtime.us-east-1.kiro.dev", "/a/../b", false},
		{"runtime.us-east-1.kiro.dev", "/%2e%2e/b", false},
		{"runtime.us-east-1.kiro.dev", "/a\\b", false},
		{"runtime.us-east-1.kiro.dev", "/a#fragment", false},
		{"127.0.0.1", "/", false},
	}
	for _, tt := range tests {
		t.Run(tt.host+tt.path, func(t *testing.T) {
			u, err := URL(tt.host, tt.path)
			if (err == nil) != tt.allowed {
				t.Fatalf("allowed=%v error=%v", tt.allowed, err)
			}
			if err == nil && (u.Host != tt.host || u.Scheme != "https") {
				t.Fatal("destination changed")
			}
		})
	}
}

func TestPrivateNetworks(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "172.16.0.1", "192.168.1.1", "100.100.100.200", "0.0.0.0", "224.0.0.1", "192.0.2.1", "198.18.0.1", "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "2001:db8::1", "64:ff9b::a00:1"} {
		if PublicIP(netip.MustParseAddr(value)) {
			t.Fatalf("accepted %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !PublicIP(netip.MustParseAddr(value)) {
			t.Fatalf("rejected %s", value)
		}
	}
}

func TestHeaders(t *testing.T) {
	for _, name := range []string{"Host", "Connection", "Proxy-Authorization", "Forwarded", "X-Forwarded-For", "Content-Length", "Transfer-Encoding"} {
		if _, err := Headers(map[string]string{name: "value"}); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if _, err := Headers(map[string]string{"Authorization": "token\r\nX-Test: value"}); err == nil {
		t.Fatal("accepted header injection")
	}
	if _, err := Headers(map[string]string{"authorization": "a", "Authorization": "b"}); err == nil {
		t.Fatal("accepted duplicate header")
	}
	if _, err := Headers(map[string]string{"X-App": "cli", "X-Stainless-OS": "Linux", "Anthropic-Beta": "example", "X-Codex-Turn-Metadata": "{}"}); err != nil {
		t.Fatal(err)
	}
}

func FuzzURL(f *testing.F) {
	f.Add("api.anthropic.com", "/v1/messages?beta=true")
	f.Add("runtime.us-east-1.kiro.dev", "/example-operation")
	f.Fuzz(func(t *testing.T, host, path string) {
		u, err := URL(host, path)
		if err == nil && (!HostAllowed(u.Host) || u.Scheme != "https" || u.User != nil || u.Fragment != "") {
			t.Fatal("unsafe destination")
		}
	})
}
