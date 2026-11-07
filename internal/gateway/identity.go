package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

const maxForwardedHops = 16
const maxForwardedBytes = 2048

type proxyTrust struct {
	networks   []netip.Prefix
	configHash string
	forwarded  atomic.Uint64
	invalid    atomic.Uint64
}

type ProxyStatus struct {
	Profile           string   `json:"profile"`
	TrustedNetworks   []string `json:"trusted_networks"`
	ConfigSHA256      string   `json:"config_sha256"`
	ForwardedRequests uint64   `json:"forwarded_requests"`
	InvalidHeaders    uint64   `json:"invalid_headers"`
}

type clientIdentity struct {
	IP        string
	Port      int
	PeerIP    string
	Scheme    string
	Forwarded bool
	Invalid   bool
}

func newProxyTrust(networks []string) (*proxyTrust, error) {
	if len(networks) > 32 {
		return nil, errors.New("trusted proxies are limited to 32 CIDRs")
	}
	trust := &proxyTrust{}
	seen := map[string]bool{}
	names := []string{}
	for _, raw := range networks {
		if len(raw) > 80 {
			return nil, errors.New("trusted proxy CIDR exceeds length limit")
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, errors.New("trusted proxies require canonical CIDRs with a nonzero prefix length")
		}
		name := prefix.String()
		if seen[name] {
			return nil, errors.New("duplicate trusted proxy CIDR")
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		prefix, _ := netip.ParsePrefix(name)
		trust.networks = append(trust.networks, prefix)
	}
	sum := sha256.Sum256([]byte("xff-v1\n" + strings.Join(names, "\n")))
	trust.configHash = hex.EncodeToString(sum[:])
	return trust, nil
}

func (p *proxyTrust) contains(addr netip.Addr) bool {
	for _, network := range p.networks {
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

func (p *proxyTrust) resolve(r *http.Request) clientIdentity {
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	clientPort, _ := strconv.Atoi(port)
	peer, err := netip.ParseAddr(ip)
	if err == nil {
		peer = peer.Unmap().WithZone("")
		ip = peer.String()
	}
	identity := clientIdentity{IP: ip, PeerIP: ip, Port: clientPort, Scheme: "http"}
	if r.TLS != nil {
		identity.Scheme = "https"
	}
	if err != nil || !p.contains(peer) {
		return identity
	}
	xff := r.Header.Values("X-Forwarded-For")
	proto := r.Header.Values("X-Forwarded-Proto")
	if len(xff) == 0 && len(proto) == 0 {
		return identity
	}
	invalid := func() clientIdentity { identity.Invalid = true; p.invalid.Add(1); return identity }
	if len(xff) == 0 || len(xff) > maxForwardedHops || len(proto) > 1 {
		return invalid()
	}
	size := len(xff) - 1
	for _, value := range xff {
		size += len(value)
	}
	if size > maxForwardedBytes {
		return invalid()
	}
	parts := strings.Split(strings.Join(xff, ","), ",")
	if len(parts) > maxForwardedHops {
		return invalid()
	}
	hops := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, err := netip.ParseAddr(strings.Trim(part, " \t"))
		if err != nil || addr.Zone() != "" {
			return invalid()
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() {
			return invalid()
		}
		hops = append(hops, addr)
	}
	if len(proto) == 1 {
		if proto[0] != "http" && proto[0] != "https" {
			return invalid()
		}
		identity.Scheme = proto[0]
	}
	// Walk from our configured network trust boundary toward the client. Values to
	// the left of the first untrusted address cannot replace that address.
	selected := peer
	for i := len(hops) - 1; i >= 0; i-- {
		if !p.contains(selected) {
			break
		}
		selected = hops[i]
	}
	identity.IP = selected.String()
	identity.Port = 0
	identity.Forwarded = true
	p.forwarded.Add(1)
	return identity
}

func (g *Gateway) ProxyStatus() ProxyStatus {
	status := ProxyStatus{Profile: "xff-v1", TrustedNetworks: []string{}, ConfigSHA256: g.proxyTrust.configHash, ForwardedRequests: g.proxyTrust.forwarded.Load(), InvalidHeaders: g.proxyTrust.invalid.Load()}
	for _, network := range g.proxyTrust.networks {
		status.TrustedNetworks = append(status.TrustedNetworks, network.String())
	}
	return status
}

func writeForwardedIdentity(headers http.Header, identity clientIdentity, host string) {
	for _, name := range []string{"Forwarded", "True-Client-IP", "CF-Connecting-IP", "Fastly-Client-IP", "X-Client-IP", "X-Original-Forwarded-For", "X-Forwarded-Port", "X-Forwarded-Server", "X-Forwarded-Prefix", "X-Forwarded-Ssl", "Front-End-Https"} {
		headers.Del(name)
	}
	headers.Set("X-Forwarded-For", identity.IP)
	headers.Set("X-Real-IP", identity.IP)
	headers.Set("X-Forwarded-Host", host)
	headers.Set("X-Forwarded-Proto", identity.Scheme)
}
