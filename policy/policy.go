package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

var destinations = map[string][]string{
	"chatgpt.com":                       {"/backend-api/codex/responses"},
	"api.anthropic.com":                 {"/v1/messages"},
	"daily-cloudcode-pa.googleapis.com": {"/v1internal:streamGenerateContent"},
	"openrouter.ai":                     {"/api/v1/responses", "/api/v1/chat/completions", "/api/v1/completions"},
	"ai-gateway.vercel.sh":              {"/v1/messages/count_tokens"},
	"runtime.us-east-1.kiro.dev":        {"/*"},
}

var allowedHeaders = map[string]bool{
	"Accept": true, "Content-Type": true,
	"Authorization": true, "X-Api-Key": true, "Anthropic-Version": true,
	"Anthropic-Beta": true, "User-Agent": true, "Chatgpt-Account-Id": true,
	"Openai-Beta": true, "Originator": true, "Session-Id": true,
	"X-Amz-Target": true, "X-Amz-User-Agent": true,
	"Amz-Sdk-Invocation-Id": true, "Amz-Sdk-Request": true,
	"X-Amzn-Kiro-Origin": true, "X-Amzn-Kiro-Profile": true, "X-Amzn-Codewhisperer-Optout": true,
	"X-App": true, "X-Stainless-Lang": true, "X-Stainless-Package-Version": true,
	"X-Stainless-Os": true, "X-Stainless-Arch": true, "X-Stainless-Runtime": true,
	"X-Stainless-Runtime-Version": true, "X-Stainless-Retry-Count": true,
	"X-Stainless-Timeout": true, "X-Stainless-Helper-Method": true,
	"X-Client-Request-Id": true, "X-Claude-Code-Session-Id": true,
	"Anthropic-Dangerous-Direct-Browser-Access": true,
	"Version": true, "Thread-Id": true, "X-Codex-Window-Id": true,
	"X-Codex-Installation-Id": true, "X-Openai-Internal-Codex-Responses-Lite": true,
	"X-Openai-Subagent": true, "X-Codex-Parent-Thread-Id": true, "X-Codex-Turn-Metadata": true,
}

func Hash() string {
	b, _ := json.Marshal(struct {
		Version      string
		Destinations map[string][]string
		Headers      map[string]bool
	}{"1", destinations, allowedHeaders})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func HostAllowed(host string) bool { _, ok := destinations[host]; return ok }

func URL(host, path string) (*url.URL, error) {
	paths, ok := destinations[host]
	if !ok || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n\x00#%") {
		return nil, errors.New("destination denied")
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" || strings.Contains(u.Path, "//") {
		return nil, errors.New("destination denied")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, errors.New("destination denied")
		}
	}
	match := false
	for _, p := range paths {
		if p == "/*" || p == u.Path {
			match = true
		}
	}
	if !match {
		return nil, errors.New("destination denied")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("query denied")
	}
	for k, values := range q {
		if len(values) != 1 {
			return nil, errors.New("query denied")
		}
		if host == "api.anthropic.com" && k == "beta" && values[0] == "true" {
			continue
		}
		if host == "daily-cloudcode-pa.googleapis.com" && k == "alt" && values[0] == "sse" {
			continue
		}
		return nil, errors.New("query denied")
	}
	u.Scheme, u.Host = "https", host
	return u, nil
}

func Headers(values map[string]string) (http.Header, error) {
	h := make(http.Header)
	seen := make(map[string]bool)
	if len(values) > 32 {
		return nil, errors.New("headers denied")
	}
	for k, v := range values {
		name := http.CanonicalHeaderKey(k)
		if !allowedHeaders[name] || len(v) > 8192 || strings.ContainsAny(v, "\r\n\x00") || seen[name] {
			return nil, errors.New("headers denied")
		}
		seen[name] = true
		if name == "Content-Type" && v != "application/json" {
			return nil, errors.New("content type denied")
		}
		if name == "Accept" && v != "application/json" && v != "text/event-stream" && v != "application/vnd.amazon.eventstream" && v != "*/*" {
			return nil, errors.New("accept type denied")
		}
		h.Set(name, v)
	}
	h.Set("Content-Type", "application/json")
	if h.Get("Accept") == "" {
		h.Set("Accept", "*/*")
	}
	h.Set("Accept-Encoding", "identity")
	return h, nil
}

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"),
}

func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	for _, p := range blocked {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
