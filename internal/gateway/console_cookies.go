package gateway

import (
	"net/http"
	"strings"
)

// Management and protected application listeners can share a loopback hostname.
// Browser cookies have no port boundary, so reserved console cookies never leave the proxy.
func stripConsoleCookies(headers http.Header) {
	values := headers.Values("Cookie")
	headers.Del("Cookie")
	for _, value := range values {
		kept := []string{}
		for _, part := range strings.Split(value, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name == "openwaf_session" || name == "openwaf_oidc" || name == "openwaf_passkey" {
				continue
			}
			kept = append(kept, strings.TrimSpace(part))
		}
		if len(kept) > 0 {
			headers.Add("Cookie", strings.Join(kept, "; "))
		}
	}
}

func stripConsoleSetCookies(headers http.Header) {
	values := headers.Values("Set-Cookie")
	headers.Del("Set-Cookie")
	for _, value := range values {
		name, _, _ := strings.Cut(strings.TrimSpace(value), "=")
		if name != "openwaf_session" && name != "openwaf_oidc" && name != "openwaf_passkey" {
			headers.Add("Set-Cookie", value)
		}
	}
}
