package gateway

import (
	"context"
	"errors"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"net/http"
	"strings"
)

func (g *Gateway) RecordAudit(record adminaudit.Record) (adminaudit.Record, error) {
	if g.audit == nil {
		return record, errors.New("administration auditing is disabled")
	}
	return g.audit.Append(record)
}

func (g *Gateway) AuditExportStatus() adminaudit.ExportStatus {
	if g.auditExporter == nil {
		return adminaudit.ExportStatus{Healthy: true}
	}
	return g.auditExporter.Status()
}
func (g *Gateway) WaitAuditExport(ctx context.Context) error {
	if g.auditExporter == nil {
		return nil
	}
	return g.auditExporter.Wait(ctx)
}
func (g *Gateway) AuditStatus() adminaudit.Status {
	if g.audit == nil {
		return adminaudit.Status{}
	}
	return g.audit.Status()
}

type auditResponse struct {
	actor string
	http.ResponseWriter
	status int
}

func (w *auditResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *auditResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
func auditOperation(r *http.Request) string {
	switch r.URL.Path {
	case "/api/v1/login":
		return "session.login"
	case "/api/v1/login/oidc":
		return "session.oidc.begin"
	case "/api/v1/login/passkey/begin":
		return "session.passkey.begin"
	case "/api/v1/login/passkey/finish":
		return "session.passkey.login"
	case "/api/v1/me/passkeys/begin", "/api/v1/me/passkeys/finish", "/api/v1/me/passkeys/revoke":
		return "passkey.change.request"
	case "/api/v1/accounts/passkeys-reset":
		return "passkey.recover.request"
	case "/api/v1/accounts/oidc":
		return "account.oidc.request"
	case "/api/v1/security-policy":
		return "security.mfa-policy.request"
	case "/api/v1/logout":
		return "session.logout"
	case "/api/v1/config", "/api/v1/config/apply":
		return "policy.apply.request"
	case "/api/v1/config/validate":
		return "policy.validate"
	case "/api/v1/config/rollback":
		return "policy.rollback.request"
	case "/api/v1/certificates/reload":
		return "certificate.reload.request"
	case "/api/v1/applications":
		return "application.create.request"
	case "/api/v1/accounts":
		return "account.save.request"
	case "/api/v1/me/password":
		return "account.password.request"
	case "/api/v1/tokens":
		return "automation.create.request"
	case "/api/v1/me/mfa/setup", "/api/v1/me/mfa/enable", "/api/v1/me/mfa/disable":
		return "account.mfa.request"
	case "/api/v1/accounts/mfa-reset":
		return "account.mfa.recover.request"
	default:
		if strings.HasPrefix(r.URL.Path, "/api/v1/tokens/") {
			return "automation.revoke.request"
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/applications/") {
			return "application.delete.request"
		}
		return "api.mutation"
	}
}
