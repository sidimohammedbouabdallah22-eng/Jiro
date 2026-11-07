package operations

import (
	"context"
	"errors"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

// ReplayAudit exports a stopped journal or archive without rewriting its records.
func ReplayAudit(ctx context.Context, path string, options eventstore.ExportOptions) (adminaudit.ExportStatus, error) {
	if err := options.Validate(); err != nil {
		return adminaudit.ExportStatus{}, err
	}
	if options.URL == "" || len(options.Token) < 32 {
		return adminaudit.ExportStatus{}, errors.New("audit replay requires a destination and a credential of at least 32 characters")
	}
	if err := regular(path, adminaudit.MaxBytes); err != nil {
		return adminaudit.ExportStatus{}, err
	}
	journal, err := adminaudit.OpenReadOnly(path)
	if err != nil {
		return adminaudit.ExportStatus{}, err
	}
	defer journal.Close()
	if journal.Status().Records == 0 {
		return adminaudit.ExportStatus{Enabled: true, Healthy: true}, nil
	}
	exporter, err := adminaudit.NewReplayExporter(journal, options)
	if err != nil {
		return adminaudit.ExportStatus{}, err
	}
	defer exporter.Close()
	err = exporter.Wait(ctx)
	return exporter.Status(), err
}
