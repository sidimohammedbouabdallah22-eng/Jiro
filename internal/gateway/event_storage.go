package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

var staticMessage = regexp.MustCompile(`(?i)\bmsg\s*:\s*'([^']*)'`)

func ruleLabel(raw string) string {
	match := staticMessage.FindStringSubmatch(raw)
	if len(match) > 1 {
		return clip(match[1], 256)
	}
	return "Security rule matched"
}
func clip(value string, n int) string {
	if len(value) > n {
		return strings.Clone(value[:n])
	}
	return strings.Clone(value)
}
func boundedEvent(e Event) Event {
	clip := func(value string, n int) string {
		if len(value) > n {
			e.Truncated = true
			return strings.Clone(value[:n])
		}
		return strings.Clone(value)
	}
	e.ID = clip(e.ID, 128)
	e.Host = clip(e.Host, 320)
	e.IP = clip(e.IP, 64)
	e.PeerIP = clip(e.PeerIP, 64)
	e.ProxyConfigSHA256 = clip(e.ProxyConfigSHA256, 64)
	e.Method = clip(e.Method, 32)
	e.Path = clip(e.Path, 2048)
	e.ApplicationID = clip(e.ApplicationID, 64)
	e.Reason = clip(e.Reason, 512)
	if len(e.Matches) > 24 {
		e.Matches = e.Matches[:24]
		e.Truncated = true
	}
	for i := range e.Matches {
		m := &e.Matches[i]
		m.Message = clip(m.Message, 256)
		if len(m.Targets) > 8 {
			m.Targets = m.Targets[:8]
			e.Truncated = true
		}
		if len(m.Tags) > 8 {
			m.Tags = m.Tags[:8]
			e.Truncated = true
		}
		for j := range m.Targets {
			m.Targets[j] = clip(m.Targets[j], 128)
		}
		for j := range m.Tags {
			m.Tags[j] = clip(m.Tags[j], 128)
		}
	}
	return e
}
func serializeEvent(e Event) (Event, []byte) {
	e = boundedEvent(e)
	for {
		data, _ := json.Marshal(e)
		if len(data) <= eventstore.MaxRecordBytes {
			return e, data
		}
		e.Truncated = true
		if len(e.Matches) > 0 {
			e.Matches = e.Matches[:len(e.Matches)/2]
		} else {
			e.Path = clip(e.Path, 256)
			e.Reason = clip(e.Reason, 128)
		}
	}
}
func (g *Gateway) StorageStatus() eventstore.Status {
	if g.eventStore == nil {
		return eventstore.Status{Enabled: false, Healthy: true}
	}
	return g.eventStore.Status()
}

type EventPage struct {
	Items      []Event `json:"items"`
	NextBefore int64   `json:"next_before,omitempty"`
	HasMore    bool    `json:"has_more"`
}

func (g *Gateway) QueryEvents(ctx context.Context, q eventstore.Query) (EventPage, error) {
	page := EventPage{Items: []Event{}}
	if g.eventStore == nil {
		return page, errors.New("durable event storage is disabled")
	}
	limit := q.Limit
	if limit < 1 || limit > 499 {
		limit = 100
	}
	q.Limit = limit + 1
	rows, err := g.eventStore.Query(ctx, q)
	if err != nil {
		return page, err
	}
	page.HasMore = len(rows) > limit
	if page.HasMore {
		rows = rows[:limit]
	}
	for _, row := range rows {
		var e Event
		if err = json.Unmarshal(row.Data, &e); err != nil {
			return page, errors.New("stored event failed decoding")
		}
		e.Sequence = row.Sequence
		page.Items = append(page.Items, e)
	}
	if page.HasMore && len(rows) > 0 {
		page.NextBefore = rows[len(rows)-1].Sequence
	}
	return page, nil
}
func (g *Gateway) FlushEvents(ctx context.Context) error {
	if err := g.flushOverloads(ctx); err != nil {
		return err
	}
	if g.eventStore == nil {
		return nil
	}
	return g.eventStore.Flush(ctx)
}

func (g *Gateway) WaitEventExport(ctx context.Context) error {
	if err := g.FlushEvents(ctx); err != nil {
		return err
	}
	if g.eventStore == nil {
		return nil
	}
	return g.eventStore.WaitExport(ctx)
}
