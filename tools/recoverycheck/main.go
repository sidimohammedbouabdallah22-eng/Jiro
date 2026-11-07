// This is a schema-1 reader fixture for recovery qualification, not a historical
// release and not a serving WAF. It deliberately cannot read schema 2.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/operations"
)

func main() {
	capabilities := flag.Bool("capabilities-json", false, "Describe this test-only schema-1 reader")
	probe := flag.Bool("upgrade-probe", false, "Read and compile a restored schema-1 state without migration")
	policy := flag.String("config", "", "Policy path")
	events := flag.String("event-db", "", "Schema-1 event database")
	audit := flag.String("audit-file", "", "Administration journal")
	policyOnly := flag.Bool("probe-policy-only", false, "Policy only")
	collector := flag.String("probe-collector", "", "Unsupported in schema-1 fixture")
	flag.Parse()
	caps := operations.CurrentCapabilities()
	caps.SenderMax = 1
	caps.PolicySchemas = []int{1}
	caps.TrafficControls = 0
	caps.AccountsFormat = 0
	caps.AuditExport = 0
	if *capabilities {
		json.NewEncoder(os.Stdout).Encode(caps)
		return
	}
	if !*probe {
		log.Fatal("test fixture only: no listener or production mode exists")
	}
	if *collector != "" {
		log.Fatal("schema-1 fixture has no collector support")
	}
	paths := operations.Paths{Policy: *policy, Audit: *audit}
	if !*policyOnly {
		paths.Events = *events
	}
	state, err := operations.Inspect(context.Background(), paths, true)
	if err != nil {
		log.Fatal(err)
	}
	if state.Events != nil && state.Events.Schema != 1 {
		log.Fatal("schema-1 fixture refuses a migrated database")
	}
	if state.Policy.Schema != 1 || len(state.Policy.PolicySchemas) > 0 {
		log.Fatal("schema-1 fixture refuses schema-2 policy history")
	}
	if state.Accounts != nil || state.Policy.TrafficControls {
		log.Fatal("legacy fixture refuses account or traffic-control state")
	}
	if err = json.NewEncoder(os.Stdout).Encode(operations.CheckReport{Compatible: true, Capabilities: caps, Before: state, After: state}); err != nil {
		log.Fatal(err)
	}
}
