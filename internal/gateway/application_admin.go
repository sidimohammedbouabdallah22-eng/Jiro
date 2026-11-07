package gateway

import (
	"net/http"
	"strings"
)

func (a *Admin) createApplication(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Revision      uint64   `json:"revision"`
		ApplicationID string   `json:"application_id"`
		Name          string   `json:"name"`
		Hosts         []string `json:"hosts"`
		Upstream      string   `json:"upstream"`
		Reason        string   `json:"reason"`
	}
	if err := decode(w, r, &request); err != nil {
		problem(w, 400, err.Error())
		return
	}
	c := a.gateway.Config()
	if request.Revision != c.Revision {
		problem(w, 409, "Configuration changed; reload before adding an application")
		return
	}
	if c.SchemaVersion != 2 {
		problem(w, 409, "Configure and save the existing application's hostnames before adding applications")
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		problem(w, 400, "A change reason is required")
		return
	}
	leaf := Defaults()
	leaf.ApplicationID = request.ApplicationID
	leaf.Name = request.Name
	leaf.Upstream = request.Upstream
	leaf.Mode = "detection"
	c.Applications = append(c.Applications, ApplicationFromConfig(leaf, request.Hosts))
	updated, err := a.gateway.ApplyWithMetadata(c, false, a.actor(r), request.Reason)
	if err != nil {
		policyProblem(w, err)
		return
	}
	reply(w, 200, updated)
}

func (a *Admin) deleteApplication(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Revision uint64 `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err := decode(w, r, &request); err != nil {
		problem(w, 400, err.Error())
		return
	}
	c := a.gateway.Config()
	if request.Revision != c.Revision {
		problem(w, 409, "Configuration changed; reload before removing an application")
		return
	}
	if c.SchemaVersion != 2 || len(c.Applications) <= 1 {
		problem(w, 409, "The deployment must retain at least one application")
		return
	}
	if strings.TrimSpace(request.Reason) == "" {
		problem(w, 400, "A change reason is required")
		return
	}
	index := -1
	for i, app := range c.Applications {
		if app.ApplicationID == r.PathValue("application") {
			index = i
			break
		}
	}
	if index < 0 {
		problem(w, 404, "Application unavailable")
		return
	}
	c.Applications = append(c.Applications[:index], c.Applications[index+1:]...)
	updated, err := a.gateway.ApplyWithMetadata(c, false, a.actor(r), request.Reason)
	if err != nil {
		policyProblem(w, err)
		return
	}
	reply(w, 200, updated)
}
