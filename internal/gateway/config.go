package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
)

// Config persists either a legacy application or a schema-2 application deployment.
type Config struct {
	SchemaVersion     int               `json:"schema_version"`
	ApplicationID     string            `json:"application_id"`
	Revision          uint64            `json:"revision"`
	Name              string            `json:"name"`
	Upstream          string            `json:"upstream"`
	Mode              string            `json:"mode"`
	Paranoia          int               `json:"paranoia"`
	InboundThreshold  int               `json:"inbound_threshold"`
	OutboundThreshold int               `json:"outbound_threshold"`
	RequestLimit      int64             `json:"request_limit"`
	ResponseLimit     int64             `json:"response_limit"`
	InspectResponse   bool              `json:"inspect_response"`
	Exclusions        []int             `json:"exclusions"`
	CustomRules       string            `json:"custom_rules"`
	ScopedExceptions  []ScopedException `json:"scoped_exceptions"`
	Applications      []Application     `json:"applications,omitempty"`
}

func Defaults() Config {
	return Config{SchemaVersion: 1, ApplicationID: "primary", Revision: 1, Name: "Primary application", Upstream: "http://127.0.0.1:3000", Mode: "enforcing", Paranoia: 1, InboundThreshold: 5, OutboundThreshold: 4, RequestLimit: 10 << 20, ResponseLimit: 1 << 20, Exclusions: []int{}, ScopedExceptions: []ScopedException{}}
}

func (c Config) Validate() error {
	if c.SchemaVersion == 2 {
		return validateApplications(c)
	}
	if c.SchemaVersion != 1 {
		return errors.New("unsupported policy schema version")
	}
	if len(c.Applications) > 0 {
		return errors.New("hostname applications require schema 2")
	}
	if c.Revision < 1 {
		return errors.New("policy revision must be positive")
	}
	if !identifier.MatchString(c.ApplicationID) {
		return errors.New("application_id must contain 1–64 letters, numbers, underscores or hyphens")
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("upstream must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(c.Name) == "" || len(c.Name) > 100 {
		return errors.New("application name must contain 1–100 characters")
	}
	if c.Mode != "enforcing" && c.Mode != "detection" && c.Mode != "disabled" {
		return errors.New("mode must be enforcing, detection, or disabled")
	}
	if c.Paranoia < 1 || c.Paranoia > 4 {
		return errors.New("paranoia must be between 1 and 4")
	}
	if c.InboundThreshold < 1 || c.InboundThreshold > 100 || c.OutboundThreshold < 1 || c.OutboundThreshold > 100 {
		return errors.New("thresholds must be between 1 and 100")
	}
	if c.RequestLimit < 1024 || c.RequestLimit > 64<<20 || c.ResponseLimit < 1024 || c.ResponseLimit > 16<<20 {
		return errors.New("body limits: request 1 KiB–64 MiB; response 1 KiB–16 MiB")
	}
	if len(c.CustomRules) > 64<<10 || len(c.Exclusions) > 200 {
		return errors.New("policy exceeds custom-rule or exclusion limits")
	}
	seen := map[int]bool{}
	for _, id := range c.Exclusions {
		if id < 900000 || id > 999999 || seen[id] {
			return errors.New("exclusions must be unique CRS IDs between 900000 and 999999")
		}
		seen[id] = true
	}
	if err := validateScoped(c.ScopedExceptions); err != nil {
		return err
	}
	// Custom rules are SecRule/SecAction only. Do not expose filesystem, audit-log,
	// engine-disable or Include directives through the management editor.
	for _, line := range strings.Split(c.CustomRules, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !strings.HasPrefix(t, "SecRule ") && !strings.HasPrefix(t, "SecAction ") {
			return errors.New("custom rules must be single-line SecRule or SecAction statements")
		}
		lower := strings.ToLower(t)
		if strings.Contains(lower, "ctl:") || strings.Contains(lower, "exec:") {
			return errors.New("ctl and exec actions are not supported in custom rules")
		}
	}
	return nil
}

// Directives is the single policy compiler used by production and connector checks.
// Include aliases are resolved against the pinned embedded filesystem by compile.
func Directives(c Config) (string, error) {
	if c.SchemaVersion != 1 {
		return "", errors.New("SecLang directives require a single schema-1 application policy")
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	mode := map[string]string{"enforcing": "On", "detection": "DetectionOnly", "disabled": "Off"}[c.Mode]
	response := "Off"
	if c.InspectResponse {
		response = "On"
	}
	// Coraza's buffered-write boundary is exclusive (>=), while policy limits
	// are inclusive. The connector checks request/inspected-response bytes before
	// passing them to Coraza, so one sentinel byte admits the final allowed byte
	// without admitting any body over the configured policy limit.
	directives := fmt.Sprintf(`Include @coraza.conf-recommended
SecRuleEngine %s
SecAuditEngine Off
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 64
SecArgumentsLimit 256
SecResponseBodyAccess %s
SecResponseBodyLimit %d
SecResponseBodyLimitAction Reject
SecResponseBodyMimeType text/plain text/html application/json application/xml text/xml
SecAction "id:100001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"
Include @crs-setup.conf.example
`, mode, c.RequestLimit+1, min(c.RequestLimit, 128<<10), response, c.ResponseLimit+1, c.Paranoia, c.Paranoia, c.InboundThreshold, c.OutboundThreshold)
	// Local rules run before CRS blocking evaluation; removals follow all includes.
	directives += scopedDirectives(c.ScopedExceptions) + c.CustomRules + "\nInclude @owasp_crs/*.conf\n"
	for _, id := range c.Exclusions {
		directives += fmt.Sprintf("SecRuleRemoveById %d\n", id)
	}
	return directives, nil
}

func compile(c Config) (coraza.WAF, error) {
	directives, err := Directives(c)
	if err != nil {
		return nil, err
	}
	return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)).WithDirectives(directives))
}

// CheckPolicy compiles an existing policy without acquiring its write lease,
// creating history, changing files, starting listeners or requiring credentials.
func CheckPolicy(path string) (Config, error) {
	if _, err := os.Stat(path); err != nil {
		return Config{}, err
	}
	c, err := load(path)
	if err != nil {
		return Config{}, err
	}
	deployment, err := buildRuntime(c, compile)
	if err != nil {
		return Config{}, err
	}
	closeRuntime(deployment)
	return c.clone(), nil
}

func load(path string) (Config, error) {
	c := Defaults()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return c, errors.New("policy file must contain exactly one JSON object")
	}
	return c, c.Validate()
}

func persist(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
