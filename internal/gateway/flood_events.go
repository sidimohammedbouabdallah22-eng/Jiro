package gateway

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/eventstore"
)

func (g *Gateway) persistEvent(parent context.Context, e Event) error {
	if e.Occurrences == 0 {
		e.Occurrences = 1
	}
	e, data := serializeEvent(e)
	g.mu.Lock()
	g.events = append([]Event{e}, g.events...)
	if len(g.events) > 500 {
		g.events = g.events[:500]
	}
	g.mu.Unlock()
	if g.eventStore == nil {
		return nil
	}
	err := g.eventStore.Append(parent, eventstore.Record{ID: e.ID, Time: e.Time, Action: e.Action, IP: e.IP, Path: e.Path, Data: data, Occurrences: e.Occurrences})
	if err != nil {
		n := g.persistenceFailures.Add(1)
		if n == 1 || n%1000 == 0 {
			log.Printf("Security event persistence errors=%d: %v", n, err)
		}
	}
	return err
}

// Capacity rejections have no inspected rule evidence. Count every rejection,
// retaining common metadata, rather than flooding disk with identical rows.
// Application/revision/action keys are bounded even during hostile policy churn.
type rejectionKey struct {
	revision            uint64
	application, action string
}

func (g *Gateway) recordOverload(e Event) {
	e = boundedEvent(e)
	g.mu.Lock()
	g.total++
	g.securitySeen++
	if e.Action == "unrouted" {
		g.unrouted++
	} else if e.Action == "rate_limited" {
		g.rateLimited++
	} else {
		g.overloaded++
	}
	minute := time.Now().Unix() / 60
	b := &g.buckets[minute%60]
	if b.Minute != minute {
		*b = Bucket{Minute: minute}
	}
	b.Requests++
	g.mu.Unlock()
	g.rollupMu.Lock()
	defer g.rollupMu.Unlock()
	key := rejectionKey{revision: e.PolicyRevision, application: e.ApplicationID, action: e.Action}
	if _, exists := g.rollups[key]; !exists && len(g.rollups) >= 61 {
		key = rejectionKey{application: "*", action: e.Action}
		e.PolicyRevision = 0
		e.ApplicationID = "*"
		e.Reason = "Capacity rejections across policy revisions and applications"
		if e.Action == "unrouted" {
			e.Reason = "Unrouted requests across policy revisions"
		}
		if e.Action == "rate_limited" {
			e.Reason = "Rate rejections across policy revisions and applications"
		}
	}
	current, exists := g.rollups[key]
	if !exists {
		e.Aggregated = true
		e.Occurrences = 1
		e.LastSeen = e.Time
		g.rollups[key] = e
		return
	}
	current.Occurrences++
	current.LastSeen = e.Time
	if current.Status != e.Status {
		current.Status = 0
		current.Reason = "Aggregated rejections with different status codes"
	} else if current.Reason != e.Reason && current.Status != 0 {
		current.Reason = "Aggregated capacity rejections with different reasons"
	}
	if current.IP != e.IP {
		current.IP = "*"
	}
	if current.PeerIP != e.PeerIP {
		current.PeerIP = "*"
	}
	if current.Host != e.Host {
		current.Host = "*"
	}
	if current.Path != e.Path {
		current.Path = "*"
	}
	if current.Method != e.Method {
		current.Method = "*"
	}
	if current.ApplicationID != e.ApplicationID {
		current.ApplicationID = "*"
	}
	g.rollups[key] = current
}
func (g *Gateway) flushOverloads(ctx context.Context) error {
	g.rollupFlush.Lock()
	defer g.rollupFlush.Unlock()
	g.rollupMu.Lock()
	events := g.rollups
	g.rollups = map[rejectionKey]Event{}
	g.rollupMu.Unlock()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for _, e := range events {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.persistEvent(ctx, e); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return first
}
func (g *Gateway) startOverloadWorker() {
	g.rollups = map[rejectionKey]Event{}
	g.rollupStop = make(chan struct{})
	g.rollupDone = make(chan struct{})
	go func() {
		defer close(g.rollupDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-g.rollupStop:
				_ = g.flushOverloads(context.Background())
				return
			case <-ticker.C:
				_ = g.flushOverloads(context.Background())
			}
		}
	}()
}
