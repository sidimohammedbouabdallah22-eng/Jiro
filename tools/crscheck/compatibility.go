package main

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
)

// These are concrete platform expectations, never ignored/force-passed tests.
// Every adapted case still runs through the real listener and must satisfy its
// replacement status/rule assertions. Original and effective expectations are
// both recorded. Keep this table reviewed with the pinned corpus version.
func platformCase(original schema.Test) (schema.Test, string) {
	tc := original
	tc.Stages = append([]schema.Stage{}, original.Stages...)
	reason := ""
	switch tc.IdString() {
	case "920100-4", "920100-5":
		reason = "OpenWAF is an application reverse proxy; CONNECT tunnelling is rejected independently of rule mode"
		tc.Stages[0].Output = schema.Output{Status: 405, Log: schema.Log{NoExpectIds: []uint{920100}}}
	case "920270-4":
		reason = "Detection-only fixture: Coraza logs the invalid-character rule instead of Apache's unconditional 400"
		tc.Stages[0].Output = schema.Output{Status: 200, Log: schema.Log{ExpectIds: []uint{920270}}}
	case "920274-1":
		reason = "Detection-only fixture: Coraza records invalid Host characters through rule 920274"
		tc.Stages[0].Output = schema.Output{Status: 200, Log: schema.Log{ExpectIds: []uint{920274}}}
	case "920290-1", "920290-4":
		reason = "Go collapses missing and empty Host into an empty Request.Host; Coraza must flag missing Host through 920280"
		tc.Stages[0].Output = schema.Output{Status: 200, Log: schema.Log{ExpectIds: []uint{920280}}}
	case "920280-3", "920430-3", "920430-8", "920430-9":
		reason = "Go rejects unsupported HTTP protocol versions before WAF evaluation with 505"
		tc.Stages[0].Output = schema.Output{Status: 505, Log: schema.Log{NoExpectIds: []uint{920430}}}
	case "920430-5":
		reason = "Go rejects the malformed request line with an HTTP 400 response before WAF evaluation"
		no := false
		tc.Stages[0].Output = schema.Output{Status: 400, ExpectError: &no, Log: schema.Log{NoExpectIds: []uint{920430}}}
	case "920620-1":
		reason = "Go preserves separate Content-Type headers; Coraza correctly detects the duplicate instead of Apache's concatenated representation"
		tc.Stages[0].Output = schema.Output{Status: 200, Log: schema.Log{ExpectIds: []uint{920620}}}
	case "922130-1", "922130-2", "922130-7":
		reason = "Coraza's multipart parser rejects invalid part headers before CRS variable matching; parser protection rules 200002 and 200003 must match"
		tc.Stages[0].Output = schema.Output{Status: 200, Log: schema.Log{ExpectIds: []uint{200002, 200003}}}
	case "921140-1":
		reason = "go-ftw 2.6.2 refuses raw CR in structured header values; send the original malicious header bytes through encoded_request without changing the expected response"
		in := tc.Stages[0].Input
		method := "GET"
		if in.Method != nil {
			method = *in.Method
		}
		uri := "/"
		if in.URI != nil {
			uri = *in.URI
		}
		version := "HTTP/1.1"
		if in.Version != nil {
			version = *in.Version
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s %s\r\n", method, uri, version)
		keys := []string{}
		for key := range in.Headers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(&b, "%s: %s\r\n", key, in.Headers[key])
		}
		b.WriteString("\r\n")
		in.EncodedRequest = base64.StdEncoding.EncodeToString([]byte(b.String()))
		tc.Stages[0].Input = in
	}
	return tc, reason
}
