package gateway

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

func normalizeHostname(value string) (string, error) {
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Zone() != "" || (!addr.IsGlobalUnicast() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast()) {
			return "", errors.New("invalid IP hostname")
		}
		return addr.Unmap().String(), nil
	}
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New("invalid hostname length")
	}
	numeric := true
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, char := range label {
			if char < '0' || char > '9' {
				numeric = false
			}
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", errors.New("hostname requires ASCII DNS labels")
			}
		}
	}
	if numeric {
		return "", errors.New("numeric hostname requires a canonical IP literal")
	}
	return name, nil
}

func requestAuthority(value string) (host, authority string, err error) {
	if len(value) == 0 || len(value) > 320 {
		return "", "", errors.New("invalid authority length")
	}
	raw, port := value, ""
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		raw = value[1 : len(value)-1]
	} else if strings.Contains(value, ":") {
		raw, port, err = net.SplitHostPort(value)
		if err != nil || port == "" {
			return "", "", errors.New("invalid authority port")
		}
	}
	host, err = normalizeHostname(raw)
	if err != nil {
		return "", "", err
	}
	if strings.HasPrefix(value, "[") {
		addr, e := netip.ParseAddr(raw)
		if e != nil || !addr.Is6() {
			return "", "", errors.New("brackets require an IPv6 literal")
		}
	}
	authority = host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		for _, char := range port {
			if char < '0' || char > '9' {
				return "", "", errors.New("invalid authority port")
			}
		}
		number, e := strconv.Atoi(port)
		if e != nil || number < 1 || number > 65535 {
			return "", "", errors.New("invalid authority port")
		}
		authority = net.JoinHostPort(host, strconv.Itoa(number))
	}
	return host, authority, nil
}

func buildRuntime(c Config, factory func(Config) (coraza.WAF, error)) (*runtime, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c = c.clone()
	if c.SchemaVersion == 1 {
		waf, err := factory(c)
		if err != nil {
			return nil, err
		}
		target, _ := url.Parse(c.Upstream)
		return &runtime{config: c, waf: waf, target: target}, nil
	}
	deployment := &runtime{config: c, applications: map[string]*runtime{}, hosts: map[string]*runtime{}}
	for _, app := range c.Applications {
		leaf, err := buildRuntime(app.config(c.Revision), factory)
		if err != nil {
			closeRuntime(deployment)
			return nil, err
		}
		if app.Pool != nil {
			leaf.pool = newUpstreamRuntime(*app.Pool)
		}
		deployment.applications[app.ApplicationID] = leaf
		if app.TrafficControls != nil {
			leaf.traffic = *app.TrafficControls
		}
		for _, host := range app.Hosts {
			deployment.hosts[host] = leaf
		}
		if deployment.waf == nil {
			deployment.waf = leaf.waf
			deployment.target = leaf.target
		}
	}
	return deployment, nil
}

func closeRuntime(deployment *runtime) {
	if deployment.applications == nil {
		if deployment.pool != nil {
			deployment.pool.close()
		}
		closeWAF(deployment.waf)
		return
	}
	for _, app := range deployment.applications {
		if app.pool != nil {
			app.pool.close()
		}
		closeWAF(app.waf)
	}
}

func (deployment *runtime) selectApplication(r *http.Request) (*runtime, string, int) {
	if deployment.config.SchemaVersion == 1 {
		return deployment, "", 0
	}
	host, authority, err := requestAuthority(r.Host)
	if err != nil || r.URL.IsAbs() || r.URL.Host != "" {
		return nil, "", http.StatusBadRequest
	}
	if r.TLS != nil && r.TLS.ServerName != "" {
		sni, err := normalizeHostname(r.TLS.ServerName)
		if err != nil || sni != host {
			return nil, authority, http.StatusMisdirectedRequest
		}
	}
	app := deployment.hosts[host]
	if app == nil {
		return nil, authority, http.StatusMisdirectedRequest
	}
	return app, authority, 0
}
