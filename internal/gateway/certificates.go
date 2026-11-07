package gateway

import "github.com/sidimohammedbouabdallah22-eng/Jiro/internal/certificates"

func (g *Gateway) SetCertificates(manager *certificates.Manager) error {
	g.update.Lock()
	defer g.update.Unlock()
	return manager.WithApplicationNames(g.active.Load().config.ApplicationHosts(), func() error { g.certificates.Store(manager); return nil })
}
func (g *Gateway) CertificateStatus() certificates.Status {
	if manager := g.certificates.Load(); manager != nil {
		return manager.Status()
	}
	return certificates.Status{Healthy: true}
}
