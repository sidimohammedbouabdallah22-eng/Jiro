// crscheck runs the pinned upstream corpus against a real OpenWAF listener.
// Its CRS-required detection-only/PL4 profile and marker rules exist only here.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crstests "github.com/corazawaf/coraza-coreruleset/crs/tests/v4"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	albedo "github.com/coreruleset/albedo/server"
	schema "github.com/coreruleset/ftw-tests-schema/v2/types"
	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/coreruleset/go-ftw/v2/runner"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/jcchavezs/mergefs"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/engineinfo"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
	"github.com/rs/zerolog"
)

type caseResult struct {
	Adaptation        string          `json:"adaptation,omitempty"`
	EffectiveExpected []schema.Output `json:"effective_expected,omitempty"`
	ID                string          `json:"id"`
	File              string          `json:"file"`
	Result            string          `json:"result"`
	Error             string          `json:"error,omitempty"`
	Expected          []schema.Output `json:"expected"`
	ActualRules       [][]uint        `json:"actual_rules"`
	Status            int             `json:"actual_status,omitempty"`
}
type report struct {
	Adapted                                         int    `json:"adapted_cases"`
	CRS                                             string `json:"crs"`
	Engine                                          string `json:"engine"`
	Framework                                       string `json:"framework"`
	Profile                                         string `json:"profile"`
	Total, Passed, Failed, Skipped, Ignored, Errors int
	Cases                                           []caseResult `json:"cases"`
	Seconds                                         float64      `json:"seconds"`
}

func run() error {
	out := flag.String("out", "../../artifacts/crs-regression.json", "Report filename")
	include := flag.String("include", "", "Optional rule/test ID regex; empty runs the entire corpus")
	raw := flag.Bool("raw", false, "Run unmodified upstream expectations without reviewed platform adaptations")
	flag.Parse()
	var filter *regexp.Regexp
	if *include != "" {
		var err error
		filter, err = regexp.Compile(*include)
		if err != nil {
			return err
		}
	}
	root, err := os.MkdirTemp("", "openwaf-crs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	logFile, err := os.Create(filepath.Join(root, "ftw.log"))
	if err != nil {
		return err
	}
	defer logFile.Close()
	var logMu sync.Mutex
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		albedo.Handler().ServeHTTP(w, r)
	}))
	defer backend.Close()
	c := gateway.Defaults()
	c.Mode = "detection"
	c.Paranoia = 4
	c.Upstream = backend.URL
	c.RequestLimit = 64 << 20
	c.ResponseLimit = 16 << 20
	c.InspectResponse = true
	b, _ := json.Marshal(c)
	policy := filepath.Join(root, "policy.json")
	if err = os.WriteFile(policy, b, 0600); err != nil {
		return err
	}
	const profile = `
SecAction "id:900005,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly,ctl:ruleRemoveById=910000,setvar:tx.blocking_paranoia_level=4,setvar:tx.detection_paranoia_level=4,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"
SecResponseBodyMimeType text/plain
SecRequestBodyJsonDepthLimit 1024
SecArgumentsLimit 1000
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:999999,phase:1,pass,t:none,log,msg:'X-CRS-Test %{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"
`
	factory := func(c gateway.Config) (coraza.WAF, error) {
		directives, err := gateway.Directives(c)
		if err != nil {
			return nil, err
		}
		directives = strings.Replace(directives, "Include @crs-setup.conf.example", profile+"\nInclude @crs-setup.conf.example", 1)
		return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)).WithDirectives(directives).WithErrorCallback(func(rule types.MatchedRule) {
			logMu.Lock()
			defer logMu.Unlock()
			_, _ = io.WriteString(logFile, rule.ErrorLog()+"\n")
		}))
	}
	g, err := gateway.NewWithOptions(policy, gateway.Options{EngineFactory: factory, DisableEventStore: true, Resources: gateway.ResourceLimits{BufferBytes: 512 << 20}})
	if err != nil {
		return err
	}
	defer g.Close(context.Background())
	front := httptest.NewUnstartedServer(g)
	front.Config.ReadHeaderTimeout = 2 * time.Second
	front.Config.ReadTimeout = 3 * time.Second
	front.Config.WriteTimeout = 5 * time.Second
	front.Config.MaxHeaderBytes = 64 << 10
	front.Start()
	defer front.Close()
	address, _ := url.Parse(front.URL)
	host := address.Hostname()
	port, _ := strconv.Atoi(address.Port())
	cfg := config.NewDefaultConfig()
	cfg.LogFile = logFile.Name()
	cfg.TestOverride.Overrides.DestAddr = &host
	cfg.TestOverride.Overrides.Port = &port
	cfg.MaxMarkerRetries = 2
	rc := config.NewRunnerConfiguration(cfg)
	rc.ReadTimeout = 2 * time.Second
	rc.ConnectTimeout = time.Second
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	r := report{CRS: "v4.30.0", Framework: "go-ftw v2.6.2", Profile: "upstream detection-only PL4 fixture profile; real HTTP listener; no force-pass/ignore; reviewed platform expectations (use -raw for unchanged upstream expectations)", Cases: []caseResult{}}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/corazawaf/coraza/v3" {
				r.Engine = engineinfo.Version()
			}
		}
	}
	start := time.Now()
	files := 0
	err = fs.WalkDir(crstests.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := fs.ReadFile(crstests.FS, path)
		if err != nil {
			return err
		}
		ft, err := test.GetTestFromYaml(data, path)
		if err != nil {
			return err
		}
		files++
		for _, original := range ft.Tests {
			tc := original
			adaptation := ""
			if !*raw {
				tc, adaptation = platformCase(original)
			}
			id := tc.IdString()
			if filter != nil && !filter.MatchString(id) {
				continue
			}
			single := *ft
			single.Tests = []schema.Test{tc}
			res, e := runner.Run(rc, []*test.FTWTest{&single}, output.NewOutput("quiet", io.Discard))
			item := caseResult{ID: id, File: path}
			item.Adaptation = adaptation
			if adaptation != "" {
				r.Adapted++
			}
			r.Total++
			for _, stage := range original.Stages {
				item.Expected = append(item.Expected, stage.Output)
			}
			if adaptation != "" {
				for _, stage := range tc.Stages {
					item.EffectiveExpected = append(item.EffectiveExpected, stage.Output)
				}
			}
			if e == nil {
				item.ActualRules = res.Stats.TriggeredRules[id]
				if res.LastStageResponse != nil {
					item.Status = res.LastStageResponse.Parsed.StatusCode
				}
			}
			switch {
			case e != nil:
				r.Errors++
				item.Result = "error"
				item.Error = e.Error()
			case len(res.Stats.Failed) > 0:
				r.Failed++
				item.Result = "failed"
			case len(res.Stats.Ignored) > 0:
				r.Ignored++
				item.Result = "ignored"
			case len(res.Stats.Skipped) > 0:
				r.Skipped++
				item.Result = "skipped"
			case len(res.Stats.Success) > 0:
				r.Passed++
				item.Result = "passed"
			default:
				r.Errors++
				item.Result = "error"
				item.Error = "unaccounted runner result"
			}
			r.Cases = append(r.Cases, item)
		}
		if files%25 == 0 {
			fmt.Printf("Files %d; cases %d; passed %d; failed %d; errors %d\n", files, r.Total, r.Passed, r.Failed, r.Errors)
		}
		return nil
	})
	if err != nil {
		return err
	}
	r.Seconds = time.Since(start).Seconds()
	if err = os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		return err
	}
	b, _ = json.MarshalIndent(r, "", "  ")
	if err = os.WriteFile(*out, b, 0644); err != nil {
		return err
	}
	fmt.Printf("CRS %s: total=%d passed=%d failed=%d skipped=%d ignored=%d errors=%d in %.1fs; report %s\n", r.CRS, r.Total, r.Passed, r.Failed, r.Skipped, r.Ignored, r.Errors, r.Seconds, *out)
	if r.Total == 0 {
		return fmt.Errorf("no corpus cases selected")
	}
	if r.Failed+r.Errors > 0 {
		return fmt.Errorf("regression failures remain; see the complete report")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
