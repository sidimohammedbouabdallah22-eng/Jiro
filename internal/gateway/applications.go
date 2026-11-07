package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const MaxApplications = 8
const MaxApplicationHosts = 16
const maxDeploymentBytes = 96 << 10

type SecurityPolicy struct {
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
}

type Application struct {
	Pool            *UpstreamPool    `json:"upstream_pool,omitempty"`
	TrafficControls *TrafficControls `json:"traffic_controls,omitempty"`
	ApplicationID   string           `json:"application_id"`
	Name            string           `json:"name"`
	Hosts           []string         `json:"hosts"`
	Upstream        string           `json:"upstream"`
	Policy          SecurityPolicy   `json:"policy"`
}

type ApplicationSummary struct {
	ApplicationID string   `json:"application_id"`
	Name          string   `json:"name"`
	Hosts         []string `json:"hosts"`
	Upstream      string   `json:"upstream"`
	Mode          string   `json:"mode"`
}

func (c Config) applicationSummaries() []ApplicationSummary {
	if c.SchemaVersion == 1 {
		return []ApplicationSummary{{ApplicationID: c.ApplicationID, Name: c.Name, Hosts: []string{}, Upstream: c.Upstream, Mode: c.Mode}}
	}
	result := make([]ApplicationSummary, 0, len(c.Applications))
	for _, app := range c.Applications {
		result = append(result, ApplicationSummary{ApplicationID: app.ApplicationID, Name: app.Name, Hosts: append([]string{}, app.Hosts...), Upstream: app.Upstream, Mode: app.Policy.Mode})
	}
	return result
}

func (c Config) inspectionState() (string, bool) {
	if c.SchemaVersion == 1 {
		return c.Mode, c.Mode != "disabled"
	}
	mode, enabled := "", true
	for _, app := range c.Applications {
		if mode == "" {
			mode = app.Policy.Mode
		} else if mode != app.Policy.Mode {
			mode = "mixed"
		}
		enabled = enabled && app.Policy.Mode != "disabled"
	}
	return mode, enabled
}

func ApplicationFromConfig(c Config, hosts []string) Application {
	c = c.clone()
	return Application{ApplicationID: c.ApplicationID, Name: c.Name, Hosts: append([]string{}, hosts...), Upstream: c.Upstream, Policy: SecurityPolicy{
		Mode: c.Mode, Paranoia: c.Paranoia, InboundThreshold: c.InboundThreshold, OutboundThreshold: c.OutboundThreshold,
		RequestLimit: c.RequestLimit, ResponseLimit: c.ResponseLimit, InspectResponse: c.InspectResponse, Exclusions: c.Exclusions, CustomRules: c.CustomRules, ScopedExceptions: c.ScopedExceptions,
	}}
}

func (a Application) config(revision uint64) Config {
	p := a.Policy
	return Config{SchemaVersion: 1, Revision: revision, ApplicationID: a.ApplicationID, Name: a.Name, Upstream: a.Upstream,
		Mode: p.Mode, Paranoia: p.Paranoia, InboundThreshold: p.InboundThreshold, OutboundThreshold: p.OutboundThreshold,
		RequestLimit: p.RequestLimit, ResponseLimit: p.ResponseLimit, InspectResponse: p.InspectResponse, Exclusions: p.Exclusions, CustomRules: p.CustomRules, ScopedExceptions: p.ScopedExceptions}
}

func (c Config) ApplicationList() []Application {
	if c.SchemaVersion == 1 {
		return []Application{ApplicationFromConfig(c, nil)}
	}
	return c.clone().Applications
}

func (c Config) ApplicationHosts() []string {
	var hosts []string
	if c.SchemaVersion == 2 {
		for _, app := range c.Applications {
			hosts = append(hosts, app.Hosts...)
		}
	}
	return hosts
}

// The legacy Go accessors describe the first application for existing callers.
// Schema-2 serialization and routing use only the explicit applications list.
func (c *Config) syncPrimary() {
	if c.SchemaVersion != 2 || len(c.Applications) == 0 {
		return
	}
	apps, revision := c.Applications, c.Revision
	*c = apps[0].config(revision)
	c.SchemaVersion = 2
	c.Applications = apps
}

type deploymentDocument struct {
	SchemaVersion int           `json:"schema_version"`
	Revision      uint64        `json:"revision"`
	Applications  []Application `json:"applications"`
}

type legacyDocument Config

func (c Config) MarshalJSON() ([]byte, error) {
	if c.SchemaVersion == 2 {
		return json.Marshal(deploymentDocument{SchemaVersion: 2, Revision: c.Revision, Applications: c.Applications})
	}
	return json.Marshal(legacyDocument(c))
}

func strictDocument(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("policy must contain exactly one JSON object")
	}
	return nil
}

func (c *Config) UnmarshalJSON(data []byte) error {
	if trimmed := strings.TrimSpace(string(data)); len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("policy must be a JSON object")
	}
	var header struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return err
	}
	if header.SchemaVersion != nil && *header.SchemaVersion == 2 {
		var document deploymentDocument
		if err := strictDocument(data, &document); err != nil {
			return err
		}
		*c = Config{SchemaVersion: 2, Revision: document.Revision, Applications: document.Applications}
		c.syncPrimary()
		return nil
	}
	legacy := legacyDocument(*c)
	if err := strictDocument(data, &legacy); err != nil {
		return err
	}
	*c = Config(legacy)
	return nil
}

func validateApplications(c Config) error {
	if c.Revision == 0 || len(c.Applications) == 0 || len(c.Applications) > MaxApplications {
		return fmt.Errorf("deployment requires a positive revision and 1..%d applications", MaxApplications)
	}
	ids, hosts := map[string]bool{}, map[string]bool{}
	for _, app := range c.Applications {
		if ids[app.ApplicationID] {
			return errors.New("application IDs must be unique")
		}
		ids[app.ApplicationID] = true
		if err := app.config(c.Revision).Validate(); err != nil {
			return fmt.Errorf("application %s: %w", app.ApplicationID, err)
		}
		if err := app.Pool.validate(app.Upstream); err != nil {
			return err
		}
		if app.TrafficControls != nil {
			if err := app.TrafficControls.validate(); err != nil {
				return err
			}
			if err := app.TrafficControls.validateBuffer(app.config(c.Revision)); err != nil {
				return err
			}
		}
		if len(app.Hosts) == 0 || len(app.Hosts) > MaxApplicationHosts {
			return fmt.Errorf("application %s requires 1..%d hostnames", app.ApplicationID, MaxApplicationHosts)
		}
		for _, host := range app.Hosts {
			normalized, err := normalizeHostname(host)
			if err != nil || normalized != host {
				return errors.New("application hosts require canonical lowercase DNS names or IP literals without ports or wildcards")
			}
			if hosts[host] {
				return fmt.Errorf("hostname %s is already assigned", host)
			}
			hosts[host] = true
		}
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if len(data) > maxDeploymentBytes {
		return errors.New("deployment exceeds the 96 KiB configuration limit")
	}
	return nil
}
