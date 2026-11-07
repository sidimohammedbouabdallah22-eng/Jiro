package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/certificates"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/operations"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "Protected application listener")
	admin := flag.String("admin", "127.0.0.1:8081", "Loopback management listener")
	trustedProxies := flag.String("trusted-proxies", "", "Comma-separated trusted proxy CIDRs using the xff-v1 header profile")
	config := flag.String("config", "config/policy.json", "Persistent policy file")
	auditFile := flag.String("audit-file", "", "Administration journal (default: policy path + .audit.jsonl)")
	auditExportURL := flag.String("audit-export-url", os.Getenv("OPENWAF_AUDIT_EXPORT_URL"), "Independent audit collector URL, HTTPS or explicit loopback HTTP")
	auditExportTokenFile := flag.String("audit-export-token-file", os.Getenv("OPENWAF_AUDIT_EXPORT_TOKEN_FILE"), "Restricted audit collector credential file; alternatively OPENWAF_AUDIT_EXPORT_TOKEN")
	startupTimeout := flag.Duration("storage-startup-timeout", eventstore.DefaultStartupTimeout, "Storage initialization budget, 1s..2m; independent of event commit deadlines")
	adminCert := flag.String("admin-tls-cert", os.Getenv("OPENWAF_ADMIN_TLS_CERT"), "Optional management-listener certificate file")
	adminKey := flag.String("admin-tls-key", os.Getenv("OPENWAF_ADMIN_TLS_KEY"), "Optional management-listener key file")
	authConfigFile := flag.String("auth-config", os.Getenv("OPENWAF_AUTH_CONFIG"), "Optional bounded OIDC/passkey configuration file")
	adminTokenFile := flag.String("admin-token-file", "", "Read administrator credential from a file instead of OPENWAF_ADMIN_TOKEN")
	exportTokenFile := flag.String("event-export-token-file", "", "Read collector credential from a file instead of OPENWAF_EVENT_EXPORT_TOKEN")
	check := flag.Bool("check-config", false, "Compile an existing policy and exit without changing files or starting listeners")
	capabilities := flag.Bool("capabilities-json", false, "Print offline upgrade/rollback compatibility information and exit")
	upgradeProbe := flag.Bool("upgrade-probe", false, "Validate and rehearse state migration on explicitly supplied disposable copies; no listeners or export")
	probeCollector := flag.String("probe-collector", "", "Disposable reference collector database for upgrade rehearsal")
	probePolicyOnly := flag.Bool("probe-policy-only", false, "Rehearse only policy/history without creating an event database")
	cert := flag.String("tls-cert", "", "Proxy TLS certificate PEM file")
	key := flag.String("tls-key", "", "Proxy TLS private key PEM file")
	tlsNames := flag.String("tls-hostnames", "", "Comma-separated expected certificate DNS names/IPs")
	tlsReloadInterval := flag.Duration("tls-reload-interval", 30*time.Second, "Certificate-file validation and reload interval (1s..1h)")
	maxConcurrent := flag.Int("max-concurrent", 64, "Maximum active application requests")
	maxConnections := flag.Int("max-connections", 256, "Maximum accepted application connections")
	bufferMiB := flag.Int64("buffer-mib", 256, "Process body-buffer admission budget in MiB")
	bodyTimeout := flag.Duration("body-timeout", 15*time.Second, "Request body read deadline")
	requestTimeout := flag.Duration("request-timeout", 60*time.Second, "Total request/upstream context deadline")
	eventDB := flag.String("event-db", "", "Event database path (default: policy path + .events.db)")
	eventMiB := flag.Int64("event-db-mib", 64, "Maximum main event database size in MiB")
	eventRows := flag.Int("event-rows", 10000, "Maximum retained security events")
	eventDays := flag.Int("event-days", 7, "Security event retention in days")
	exportURL := flag.String("event-export-url", "", "Acknowledged collector URL (HTTPS or loopback HTTP); token from OPENWAF_EVENT_EXPORT_TOKEN")
	exportRows := flag.Int("event-export-rows", 10000, "Maximum durable unacknowledged export records (never silently evicted)")
	commitTimeout := flag.Duration("event-write-timeout", 5*time.Second, "Maximum wait for a durable local security-event commit")
	flag.Parse()
	if *capabilities {
		if err := json.NewEncoder(os.Stdout).Encode(operations.CurrentCapabilities()); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *upgradeProbe {
		paths := operations.Paths{Policy: *config, Collector: *probeCollector, Audit: *auditFile}
		if !*probePolicyOnly {
			paths.Events = *eventDB
			if paths.Events == "" {
				paths.Events = *config + ".events.db"
			}
		}
		report, err := operations.Probe(context.Background(), paths)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(report); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *check {
		c, err := gateway.CheckPolicy(*config)
		if err != nil {
			log.Fatal(err)
		}
		if c.SchemaVersion == 2 {
			fmt.Printf("Policy valid: schema 2, applications %d, deployment revision %d\n", len(c.Applications), c.Revision)
		} else {
			fmt.Printf("Policy valid: schema %d, application %s, revision %d, mode %s\n", c.SchemaVersion, c.ApplicationID, c.Revision, c.Mode)
		}
		return
	}
	host, _, err := net.SplitHostPort(*admin)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("admin must bind to an explicit loopback IP; use an SSH tunnel for remote access")
	}
	token, err := secretValue("OPENWAF_ADMIN_TOKEN", *adminTokenFile)
	if err != nil {
		log.Fatal(err)
	}
	exportToken, err := secretValue("OPENWAF_EVENT_EXPORT_TOKEN", *exportTokenFile)
	if err != nil {
		log.Fatal(err)
	}
	auditToken, err := secretValue("OPENWAF_AUDIT_EXPORT_TOKEN", *auditExportTokenFile)
	if err != nil {
		log.Fatal(err)
	}
	if len(token) < 32 {
		log.Fatal("set OPENWAF_ADMIN_TOKEN to a random secret of at least 32 characters")
	}
	if (*cert == "") != (*key == "") {
		log.Fatal("tls-cert and tls-key must be provided together")
	}
	if *tlsReloadInterval < time.Second || *tlsReloadInterval > time.Hour || len(*tlsNames) > 2048 || (*tlsNames != "" && *cert == "") {
		log.Fatal("invalid TLS lifecycle settings")
	}
	if *bufferMiB < 4 || *bufferMiB > 8192 || *eventMiB < 4 || *eventMiB > 1024 || *eventDays < 1 || *eventDays > 365 {
		log.Fatal("resource or event retention flags are out of range")
	}
	var proxyNetworks []string
	if len(*trustedProxies) > 4096 {
		log.Fatal("trusted-proxies exceeds length limit")
	}
	if strings.TrimSpace(*trustedProxies) != "" {
		proxyNetworks = strings.Split(*trustedProxies, ",")
	}
	g, err := gateway.NewWithOptions(*config, gateway.Options{TrustedProxies: proxyNetworks, AuditPath: *auditFile, AuditExport: eventstore.ExportOptions{URL: *auditExportURL, Token: auditToken}, Resources: gateway.ResourceLimits{MaxConcurrent: *maxConcurrent, MaxConnections: *maxConnections, BufferBytes: *bufferMiB << 20, BodyReadTimeout: *bodyTimeout, RequestTimeout: *requestTimeout}, EventStore: eventstore.Options{Path: *eventDB, MaxBytes: *eventMiB << 20, MaxRows: *eventRows, MaxAge: time.Duration(*eventDays) * 24 * time.Hour, CommitTimeout: *commitTimeout, StartupTimeout: *startupTimeout, Export: eventstore.ExportOptions{URL: *exportURL, Token: exportToken, MaxRows: *exportRows}}})
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close(context.Background())
	certificateContext, stopCertificates := context.WithCancel(context.Background())
	defer stopCertificates()
	var certificateManager *certificates.Manager
	certificateDone := make(chan struct{})
	if *cert != "" {
		var names []string
		if *tlsNames != "" {
			for _, name := range strings.Split(*tlsNames, ",") {
				names = append(names, strings.TrimSpace(name))
			}
		}
		certificateManager, err = certificates.New(*cert, *key, names, func(outcome, fingerprint, correlation string) (string, error) {
			record, err := g.RecordAudit(adminaudit.Record{Operation: "certificate.activate", Actor: "certificate file watcher", Outcome: outcome, Resource: fingerprint, Correlation: correlation})
			return record.Correlation, err
		})
		if err != nil {
			log.Fatal(err)
		}
		if err = g.SetCertificates(certificateManager); err != nil {
			log.Fatal(err)
		}
		go func() { defer close(certificateDone); certificateManager.Run(certificateContext, *tlsReloadInterval) }()
	} else {
		close(certificateDone)
	}
	al, err := net.Listen("tcp", *admin)
	if err != nil {
		log.Fatal(err)
	}
	pl, err := net.Listen("tcp", *listen)
	if err != nil {
		_ = al.Close()
		log.Fatal(err)
	}
	pl = g.LimitListener(pl)
	authConfig, err := gateway.LoadAuthenticationConfig(*authConfigFile)
	if err != nil {
		log.Fatal(err)
	}
	adminHandler, err := gateway.NewAdminWithAuthentication(g, token, authConfig)
	if err != nil {
		log.Fatal(err)
	}
	var administrationCertificates *certificates.Manager
	administrationCertificateDone := make(chan struct{})
	if (*adminCert == "") != (*adminKey == "") {
		log.Fatal("admin-tls-cert and admin-tls-key must be provided together")
	}
	if authConfig.Origin != "" {
		origin, _ := url.Parse(authConfig.Origin)
		if (origin.Scheme == "https") != (*adminCert != "") {
			log.Fatal("authentication origin scheme must match management TLS configuration")
		}
	}
	if *adminCert != "" {
		names := []string{host}
		if authConfig.Origin != "" {
			origin, _ := url.Parse(authConfig.Origin)
			names = []string{origin.Hostname()}
		}
		administrationCertificates, err = certificates.New(*adminCert, *adminKey, names, func(outcome, fingerprint, correlation string) (string, error) {
			record, err := g.RecordAudit(adminaudit.Record{Operation: "admin.certificate.activate", Actor: "certificate file watcher", Outcome: outcome, Resource: fingerprint, Correlation: correlation})
			return record.Correlation, err
		})
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer close(administrationCertificateDone)
			administrationCertificates.Run(certificateContext, *tlsReloadInterval)
		}()
	} else {
		close(administrationCertificateDone)
	}
	as := &http.Server{Handler: adminHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	ps := &http.Server{Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	if certificateManager != nil {
		ps.TLSConfig = certificateManager.TLSConfig()
	}
	if _, err = g.RecordAudit(adminaudit.Record{Operation: "service.started", Actor: "service", Outcome: "success", Revision: g.Config().Revision, Resource: g.ProxyStatus().ConfigSHA256}); err != nil {
		log.Fatal(err)
	}
	errs := make(chan error, 2)
	if administrationCertificates != nil {
		as.TLSConfig = administrationCertificates.TLSConfig()
	}
	go func() {
		if administrationCertificates != nil {
			errs <- as.ServeTLS(al, "", "")
		} else {
			errs <- as.Serve(al)
		}
	}()
	go func() {
		if *cert != "" {
			errs <- ps.ServeTLS(pl, "", "")
		} else {
			errs <- ps.Serve(pl)
		}
	}()
	consoleOrigin := authConfig.Origin
	if consoleOrigin == "" {
		consoleOrigin = "http://" + *admin
		if administrationCertificates != nil {
			consoleOrigin = "https://" + *admin
		}
	}
	if c := g.Config(); c.SchemaVersion == 2 {
		log.Printf("OpenWAF: %d hostname-routed applications on %s; console %s; deployment revision %d", len(c.Applications), *listen, consoleOrigin, c.Revision)
	} else {
		log.Printf("OpenWAF: application %s → %s; console %s; policy revision %d", *listen, c.Upstream, consoleOrigin, c.Revision)
	}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	reload, stopReload := reloadSignals()
	defer stopReload()
	listenerFailed := false
wait:
	for {
		select {
		case <-reload:
			if administrationCertificates != nil {
				if err := administrationCertificates.Reload(); err != nil {
					log.Print("Management certificate reload failed")
				}
			}
			if certificateManager != nil {
				if err := certificateManager.Reload(); err != nil {
					log.Printf("Certificate reload failed: %v", err)
				}
			}
		case <-quit:
			break wait
		case err := <-errs:
			if err != http.ErrServerClosed {
				log.Printf("Listener failed: %v", err)
				listenerFailed = true
			}
			break wait
		}
	}
	stopCertificates()
	<-certificateDone
	<-administrationCertificateDone
	if _, err = g.RecordAudit(adminaudit.Record{Operation: "service.stopping", Actor: "service", Outcome: "intent", Revision: g.Config().Revision}); err != nil {
		log.Print("Could not persist service shutdown audit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Shutdown alone waits for active streams and does not own hijacked
	// WebSockets. Cancel gateway transactions while stopping both listeners.
	stopped := make(chan struct{}, 2)
	go func() { _ = ps.Shutdown(ctx); stopped <- struct{}{} }()
	go func() { _ = as.Shutdown(ctx); stopped <- struct{}{} }()
	g.Close(ctx)
	for i := 0; i < 2; i++ {
		select {
		case <-stopped:
		case <-ctx.Done():
		}
	}
	if ctx.Err() != nil {
		_ = ps.Close()
		_ = as.Close()
		// Closing listeners unblocks slow upload readers. Give their final
		// events a separate bounded flush window before the process exits.
		flushContext, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		g.Close(flushContext)
	}
	if listenerFailed {
		os.Exit(1)
	}
}
