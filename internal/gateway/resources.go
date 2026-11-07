package gateway

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

// ResourceLimits are process settings, separate from rollbackable rule policy.
// BufferBytes is an admission budget for connector/body copies, not a Go heap cap.
type ResourceLimits struct {
	MaxConcurrent   int           `json:"max_concurrent"`
	MaxConnections  int           `json:"max_connections"`
	BufferBytes     int64         `json:"buffer_budget_bytes"`
	BodyReadTimeout time.Duration `json:"-"`
	RequestTimeout  time.Duration `json:"-"`
}

func (r ResourceLimits) defaults() ResourceLimits {
	if r.MaxConcurrent == 0 {
		r.MaxConcurrent = 64
	}
	if r.MaxConnections == 0 {
		r.MaxConnections = 256
	}
	if r.BufferBytes == 0 {
		r.BufferBytes = 256 << 20
	}
	if r.BodyReadTimeout == 0 {
		r.BodyReadTimeout = 15 * time.Second
	}
	if r.RequestTimeout == 0 {
		r.RequestTimeout = 60 * time.Second
	}
	return r
}
func (r ResourceLimits) validate() error {
	if r.MaxConcurrent < 1 || r.MaxConcurrent > 1024 || r.MaxConnections < 1 || r.MaxConnections > 4096 || r.BufferBytes < 4<<20 || r.BufferBytes > 8<<30 || r.BodyReadTimeout < time.Second || r.BodyReadTimeout > 5*time.Minute || r.RequestTimeout < time.Second || r.RequestTimeout > 10*time.Minute {
		return errors.New("invalid process resource limits")
	}
	return nil
}

type resourceBudget struct {
	pending                                                                                           int
	pendingApps                                                                                       map[string]int
	pendingClients                                                                                    map[pendingClient]bool
	changed                                                                                           chan struct{}
	admissionEpoch, waitExpired                                                                       uint64
	waitEntered, waitAdmitted, waitCancelled, waitPolicyChanged, waitRateRefused, waitCapacityRefused uint64
	applications                                                                                      map[string]*applicationBudget
	rateRejected, fairRejected                                                                        uint64
	mu                                                                                                sync.Mutex
	limits                                                                                            ResourceLimits
	active                                                                                            int
	reserved                                                                                          int64
	rejected                                                                                          uint64
}

type pendingClient struct{ application, ip string }

func (b *resourceBudget) acquire(weight int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active >= b.limits.MaxConcurrent || weight > b.limits.BufferBytes-b.reserved {
		b.rejected++
		return false
	}
	b.active++
	b.reserved += weight
	return true
}
func (b *resourceBudget) release(weight int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active--
	b.reserved -= weight
	b.signalAdmissionLocked()
}
func bodyReservation(r *http.Request, c Config) int64 {
	return bufferReservation(requestBodySize(r, c), c)
}

func requestBodySize(r *http.Request, c Config) int64 {
	var size int64
	if r.Body != nil && r.Body != http.NoBody {
		size = r.ContentLength
		if size < 0 {
			size = c.RequestLimit
		}
		if size > c.RequestLimit {
			size = c.RequestLimit
		}
	}
	return size
}

func bufferReservation(size int64, c Config) int64 {
	reservation := 4 * (size + 1)
	if c.InspectResponse && c.Mode != "disabled" {
		reservation += 3 * (c.ResponseLimit + 1)
	}
	return reservation
}
func (g *Gateway) ResourceStatus() map[string]any {
	g.budget.mu.Lock()
	defer g.budget.mu.Unlock()
	r := g.budget.limits
	// Pending requests hold no body/transaction reservation and remain bounded
	// independently of the active request budget.
	return map[string]any{
		"max_concurrent": r.MaxConcurrent, "max_connections": r.MaxConnections,
		"buffer_budget_bytes": r.BufferBytes, "active": g.budget.active, "reserved_buffer_bytes": g.budget.reserved,
		"overload_rejections": g.budget.rejected, "fairness_rejections": g.budget.fairRejected, "rate_rejections": g.budget.rateRejected,
		"max_clients_per_application": maxClientBuckets, "body_read_timeout_seconds": r.BodyReadTimeout.Seconds(), "request_timeout_seconds": r.RequestTimeout.Seconds(),
		"pending_admissions": g.budget.pending, "max_pending_admissions": maxPendingAdmissions,
		"max_pending_per_application": maxPendingPerApplication, "max_pending_per_client": 1,
		"admission_wait_expired": g.budget.waitExpired, "admission_wait_entered": g.budget.waitEntered,
		"admission_wait_admitted": g.budget.waitAdmitted, "admission_wait_cancelled": g.budget.waitCancelled,
		"admission_wait_policy_changed": g.budget.waitPolicyChanged, "admission_wait_rate_refused": g.budget.waitRateRefused,
		"admission_wait_capacity_refused": g.budget.waitCapacityRefused,
	}
}
func (g *Gateway) LimitListener(listener net.Listener) net.Listener {
	return netutil.LimitListener(listener, g.budget.limits.MaxConnections)
}
