package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/credentials"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/operations"
)

type response struct {
	OK        bool   `json:"ok"`
	Operation string `json:"operation"`
	Result    any    `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(os.Stdout, "Usage: waf-admin backup|verify|restore|inspect|upgrade-check|rollback|audit-export [flags]\nUse <command> -h for flags. Restore/rollback require a new destination; operations never switch a running service.")
		return nil
	}
	operation := args[0]
	allowed := map[string]string{"audit-export": "audit-file export-url export-token-file", "backup": "config event-db collector-db audit-file policy-only external-collector out binary admin-token-file", "verify": "backup", "restore": "backup out", "inspect": "config event-db collector-db audit-file policy-only", "upgrade-check": "backup candidate", "rollback": "backup out candidate"}
	if _, ok := allowed[operation]; !ok {
		return fmt.Errorf("unknown operation %q", operation)
	}
	flags := flag.NewFlagSet(operation, flag.ContinueOnError)
	config := flags.String("config", "config/policy.json", "Stopped application's policy path")
	events := flags.String("event-db", "", "Sender database (default: policy path + .events.db)")
	collector := flags.String("collector-db", "", "Stopped, dedicated reference collector database for a coordinated recovery set")
	audit := flags.String("audit-file", "", "Administration journal (automatically includes the default policy path + .audit.jsonl when present)")
	exportURL := flags.String("export-url", "", "Audit replay destination, HTTPS or explicit loopback HTTP")
	exportTokenFile := flags.String("export-token-file", "", "Restricted audit collector credential file, alternatively OPENWAF_AUDIT_EXPORT_TOKEN")
	policyOnly := flags.Bool("policy-only", false, "Explicitly omit security events from backup/inspection")
	external := flags.Bool("external-collector", false, "Sender-only backup: restore must retain the current deduplicating external collector")
	backup := flags.String("backup", "", "Immutable backup directory")
	output := flags.String("out", "", "New backup/restore directory; existing destinations are never overwritten")
	binary := flags.String("binary", "", "Optional current Go executable to include in backup")
	credential := flags.String("admin-token-file", "", "Explicitly include this private administrator credential file (backup is sensitive and unencrypted)")
	candidate := flags.String("candidate", "", "Trusted target executable for rehearsal; rollback defaults to bundled binary")
	timeout := flags.Duration("timeout", 5*time.Minute, "Operation deadline (1s..30m)")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	var invalid string
	flags.Visit(func(f *flag.Flag) {
		if f.Name != "timeout" && !strings.Contains(" "+allowed[operation]+" ", " "+f.Name+" ") {
			invalid = f.Name
		}
	})
	if invalid != "" {
		return fmt.Errorf("flag -%s is not valid for %s", invalid, operation)
	}
	if *timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("timeout must be 1s..30m")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	paths := operations.Paths{Policy: *config, Events: *events, Collector: *collector, Audit: *audit}
	if *policyOnly {
		if *events != "" || *collector != "" {
			return errors.New("policy-only cannot include databases")
		}
	} else if paths.Events == "" {
		paths.Events = *config + ".events.db"
	}
	result := response{Operation: operation}
	var err error
	switch operation {
	case "audit-export":
		if *audit == "" || *exportURL == "" {
			return errors.New("audit-export requires -audit-file and -export-url")
		}
		var token string
		token, err = credentials.Value("OPENWAF_AUDIT_EXPORT_TOKEN", *exportTokenFile)
		if err == nil {
			result.Result, err = operations.ReplayAudit(ctx, *audit, eventstore.ExportOptions{URL: *exportURL, Token: token})
		}
	case "backup":
		if *output == "" {
			return errors.New("backup requires -out")
		}
		result.Result, err = operations.Backup(ctx, operations.BackupOptions{Paths: paths, Destination: *output, Binary: *binary, Credential: *credential, ExternalCollector: *external})
	case "verify":
		if *backup == "" {
			return errors.New("verify requires -backup")
		}
		result.Result, err = operations.Verify(ctx, *backup)
	case "restore":
		if *backup == "" || *output == "" {
			return errors.New("restore requires -backup and -out")
		}
		result.Result, err = operations.Restore(ctx, *backup, *output)
	case "inspect":
		result.Result, err = operations.Inspect(ctx, paths, true)
	case "upgrade-check":
		if *backup == "" || *candidate == "" {
			return errors.New("upgrade-check requires -backup and -candidate")
		}
		result.Result, err = operations.UpgradeCheck(ctx, *backup, *candidate)
	case "rollback":
		if *backup == "" || *output == "" {
			return errors.New("rollback requires -backup and -out")
		}
		result.Result, err = operations.Rollback(ctx, *backup, *output, *candidate)
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	result.OK = err == nil
	if err != nil {
		result.Error = err.Error()
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if e := encoder.Encode(result); e != nil {
		return e
	}
	return err
}
