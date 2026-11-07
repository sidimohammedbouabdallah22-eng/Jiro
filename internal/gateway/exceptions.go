package gateway

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ScopedException removes only selected rule targets for a single decoded path
// and method in this application. No path-prefix or whole-rule bypass is implied.
type ScopedException struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Collection string `json:"collection"`
	Parameter  string `json:"parameter"`
	RuleIDs    []int  `json:"rule_ids"`
	Reason     string `json:"reason"`
	Owner      string `json:"owner"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var exceptionPath = regexp.MustCompile(`^/[A-Za-z0-9/_.~-]*$`)
var parameterName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func validateScoped(exceptions []ScopedException) error {
	if len(exceptions) > 100 {
		return errors.New("at most 100 scoped exceptions are supported")
	}
	seen := map[string]bool{}
	for _, e := range exceptions {
		if !identifier.MatchString(e.ID) || seen[e.ID] {
			return errors.New("exception IDs must be unique and contain 1–64 letters, numbers, underscores or hyphens")
		}
		seen[e.ID] = true
		switch e.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			return fmt.Errorf("exception %s: select an explicit uppercase HTTP method", e.ID)
		}
		if len(e.Path) > 512 || !exceptionPath.MatchString(e.Path) {
			return fmt.Errorf("exception %s: path must be an exact decoded path using letters, numbers, /, _, ., ~ or -", e.ID)
		}
		if e.Collection != "ARGS_GET" && e.Collection != "ARGS_POST" {
			return fmt.Errorf("exception %s: collection must be ARGS_GET or ARGS_POST", e.ID)
		}
		if !parameterName.MatchString(e.Parameter) {
			return fmt.Errorf("exception %s: parameter must contain 1–128 letters, numbers, _, . or -", e.ID)
		}
		if strings.TrimSpace(e.Reason) == "" || len(e.Reason) > 500 || strings.TrimSpace(e.Owner) == "" || len(e.Owner) > 100 {
			return fmt.Errorf("exception %s: owner and reason are required (100/500 characters maximum)", e.ID)
		}
		if len(e.RuleIDs) == 0 || len(e.RuleIDs) > 30 {
			return fmt.Errorf("exception %s: select 1–30 CRS detection rule IDs", e.ID)
		}
		ids := map[int]bool{}
		for _, id := range e.RuleIDs {
			if id < 913000 || id >= 949000 || ids[id] {
				return fmt.Errorf("exception %s: rule IDs must be unique detection IDs from 913000 to 948999; blocking and initialization rules cannot be excluded here", e.ID)
			}
			ids[id] = true
		}
		if e.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, e.ExpiresAt); err != nil {
				return fmt.Errorf("exception %s: expiry must be an RFC3339 timestamp", e.ID)
			}
		}
	}
	return nil
}

func scopedDirectives(exceptions []ScopedException) string {
	var b strings.Builder
	for i, e := range exceptions {
		// Validation restricts all interpolated syntax. Metadata never becomes code.
		actions := []string{}
		for _, id := range e.RuleIDs {
			actions = append(actions, "ctl:ruleRemoveTargetById="+strconv.Itoa(id)+";"+e.Collection+":"+e.Parameter)
			actions = append(actions, "ctl:ruleRemoveTargetById="+strconv.Itoa(id)+";ARGS:"+e.Parameter)
		}
		// CRS commonly evaluates the aggregate ARGS collection. Removing only
		// ARGS_GET/ARGS_POST would not exclude that target. Evaluate in phase 2
		// after body parsing, and refuse to exclude when the same key also
		// exists in the other source. This prevents a query exception from
		// silently excluding a body field (or vice versa).
		other := "ARGS_POST"
		if e.Collection == "ARGS_POST" {
			other = "ARGS_GET"
		}
		fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@streq %s\" \"id:%d,phase:2,pass,nolog,t:none,chain\"\n", e.Path, 110000+i)
		fmt.Fprintf(&b, " SecRule REQUEST_METHOD \"@streq %s\" \"t:none,chain\"\n", e.Method)
		fmt.Fprintf(&b, " SecRule &%s:%s \"@gt 0\" \"t:none,chain\"\n", e.Collection, e.Parameter)
		if e.ExpiresAt != "" {
			expiry, _ := time.Parse(time.RFC3339, e.ExpiresAt)
			fmt.Fprintf(&b, " SecRule &%s:%s \"@eq 0\" \"t:none,chain\"\n", other, e.Parameter)
			fmt.Fprintf(&b, " SecRule TIME_EPOCH \"@lt %d\" \"t:none,%s\"\n", expiry.Unix(), strings.Join(actions, ","))
		} else {
			fmt.Fprintf(&b, " SecRule &%s:%s \"@eq 0\" \"t:none,%s\"\n", other, e.Parameter, strings.Join(actions, ","))
		}
	}
	return b.String()
}

func (c Config) clone() Config {
	c.Exclusions = append([]int{}, c.Exclusions...)
	c.ScopedExceptions = append([]ScopedException{}, c.ScopedExceptions...)
	for i := range c.ScopedExceptions {
		c.ScopedExceptions[i].RuleIDs = append([]int{}, c.ScopedExceptions[i].RuleIDs...)
	}
	if c.Applications != nil {
		c.Applications = append([]Application{}, c.Applications...)
		for i, app := range c.Applications {
			c.Applications[i] = ApplicationFromConfig(app.config(c.Revision), app.Hosts)
			if app.Pool != nil {
				pool := *app.Pool
				pool.Backends = append([]Backend{}, app.Pool.Backends...)
				c.Applications[i].Pool = &pool
			}
			if app.TrafficControls != nil {
				controls := *app.TrafficControls
				c.Applications[i].TrafficControls = &controls
			}
		}
	}
	c.syncPrimary()
	return c
}
