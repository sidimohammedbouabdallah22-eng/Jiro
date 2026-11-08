package gateway

import (
	"container/list"
	"context"
	"errors"
	"math"
	"time"
)

const maxClientBuckets = 1024

const maxPendingAdmissions = 8
const maxPendingPerApplication = 4

func hasTrafficControls(c Config) bool {
	for _, app := range c.Applications {
		if app.TrafficControls != nil {
			return true
		}
	}
	return false
}

type TrafficControls struct {
	RequestsPerSecond       int              `json:"requests_per_second"`
	Burst                   int              `json:"burst"`
	ClientRequestsPerSecond int              `json:"client_requests_per_second"`
	ClientBurst             int              `json:"client_burst"`
	ClientBodyKiBPerSecond  int              `json:"client_body_kib_per_second,omitempty"`
	ClientBodyBurstKiB      int              `json:"client_body_burst_kib,omitempty"`
	ClientBodyReservation   *BodyReservation `json:"client_body_reservation,omitempty"`
	MaxConcurrent           int              `json:"max_concurrent"`
	MaxClientConcurrent     int              `json:"max_client_concurrent"`
	MaxClientBufferMiB      int              `json:"max_client_buffer_mib,omitempty"`
	AdmissionWaitMS         int              `json:"admission_wait_ms,omitempty"`
	bodyKiB                 int
	reservedBody            bool
}

func (c TrafficControls) validate() error {
	if err := c.validateBodyReservation(); err != nil {
		return err
	}
	if c.ClientBodyKiBPerSecond < 0 || c.ClientBodyKiBPerSecond > 1048576 || c.ClientBodyBurstKiB < 0 || c.ClientBodyBurstKiB > 8388608 || (c.ClientBodyKiBPerSecond == 0) != (c.ClientBodyBurstKiB == 0) || (c.ClientBodyKiBPerSecond > 0 && int64(c.ClientBodyBurstKiB) > int64(c.ClientBodyKiBPerSecond)*600) {
		return errors.New("client body rate and burst must both be zero or bounded positive KiB values, with at most ten minutes of burst capacity")
	}
	if c.MaxClientBufferMiB < 0 || c.MaxClientBufferMiB > 8192 {
		return errors.New("client buffer budget must be 0..8192 MiB")
	}
	if c.AdmissionWaitMS < 0 || c.AdmissionWaitMS > 1000 {
		return errors.New("admission wait must be 0..1000 milliseconds")
	}
	for _, pair := range [][2]int{{c.RequestsPerSecond, c.Burst}, {c.ClientRequestsPerSecond, c.ClientBurst}} {
		if pair[0] < 0 || pair[0] > 100000 || pair[1] < 0 || pair[1] > 100000 || (pair[0] == 0) != (pair[1] == 0) || (pair[0] > 0 && pair[1] > pair[0]*600) {
			return errors.New("rate and burst must both be zero or 1..100000, with at most ten minutes of burst capacity")
		}
	}
	if c.MaxConcurrent < 0 || c.MaxConcurrent > 1024 || c.MaxClientConcurrent < 0 || c.MaxClientConcurrent > 1024 {
		return errors.New("application/client concurrency must be 0..1024")
	}
	return nil
}

func (c TrafficControls) validateBuffer(policy Config) error {
	if r := c.ClientBodyReservation; r != nil {
		if int64(r.BurstKiB)*1024 < policy.RequestLimit || int64(c.ClientBodyBurstKiB-r.BurstKiB)*1024 < policy.RequestLimit {
			return errors.New("reserved and general body bursts must each fit one maximum request")
		}
	}
	if c.ClientBodyKiBPerSecond > 0 && int64(c.ClientBodyBurstKiB)*1024 < policy.RequestLimit {
		return errors.New("client body burst must fit one maximum request")
	}
	if c.MaxClientBufferMiB > 0 && int64(c.MaxClientBufferMiB)<<20 < bufferReservation(policy.RequestLimit, policy) {
		return errors.New("client buffer budget must fit one maximum request and its inspected response")
	}
	return nil
}

type tokenBucket struct {
	tokens      float64
	updated     time.Time
	rate, burst int
}

func (b *tokenBucket) refill(now time.Time, rate, burst int) {
	if b.updated.IsZero() || b.rate == 0 {
		b.tokens = float64(burst)
	} else {
		b.tokens = math.Min(float64(b.burst), b.tokens+math.Max(0, now.Sub(b.updated).Seconds())*float64(b.rate))
	}
	b.tokens = math.Min(b.tokens, float64(burst))
	b.updated, b.rate, b.burst = now, rate, burst
}
func (b *tokenBucket) retry() int {
	return b.retryCost(1)
}
func (b *tokenBucket) retryCost(cost float64) int {
	if b.rate == 0 || b.tokens >= cost {
		return 0
	}
	return max(1, int(math.Ceil((cost-b.tokens)/float64(b.rate))))
}

type clientBudget struct {
	key                string
	active             int
	reserved           int64
	seen               time.Time
	bucket             tokenBucket
	bodyBucket         tokenBucket
	reservedBodyBucket tokenBucket
	generalBodyBucket  tokenBucket
	element            *list.Element
}
type applicationBudget struct {
	retired  bool
	active   int
	reserved int64
	bucket   tokenBucket
	clients  map[string]*clientBudget
	recent   list.List
}
type admissionResult struct {
	status  int
	reason  string
	retry   int
	release func()
}

// The budget mutex makes rate consumption and admission one atomic operation.
// Active requests retain their state pointer across application deletion/reuse.
func (b *resourceBudget) admit(id, ip string, weight int64, c TrafficControls, applications int, now time.Time) admissionResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.tryAdmitLocked(id, ip, weight, c, applications, now)
	b.countAdmissionFailureLocked(r)
	return r
}

func (b *resourceBudget) countAdmissionFailureLocked(r admissionResult) {
	if r.status == 503 {
		b.rejected++
		b.fairRejected++
	} else if r.status == 429 {
		b.rateRejected++
	}
}

// Waiting requests own no transaction or body buffer. Listener connection caps
// bound unread socket data; these caps bound the queue across client/IP churn.
func (b *resourceBudget) admitWaiting(ctx context.Context, id, ip string, weight int64, c TrafficControls, applications int) admissionResult {
	b.mu.Lock()
	key := pendingClient{id, ip}
	queued := false
	r := admissionResult{}
	defer func() {
		if queued {
			b.pending--
			b.pendingApps[id]--
			if b.pendingApps[id] == 0 {
				delete(b.pendingApps, id)
			}
			delete(b.pendingClients, key)
			if b.pending == 0 {
				b.signalAdmissionLocked()
			}
		}
		b.countAdmissionFailureLocked(r)
		b.mu.Unlock()
	}()
	if ctx.Err() != nil {
		r = admissionResult{status: 503, reason: "Admission cancelled", retry: 1}
		return r
	}
	r = b.tryAdmitLocked(id, ip, weight, c, applications, time.Now())
	if r.status != 503 || c.AdmissionWaitMS == 0 {
		return r
	}
	// A reservation which can never fit must not occupy scarce waiting space.
	if weight > b.limits.BufferBytes/int64(applications) || (c.MaxClientBufferMiB > 0 && weight > int64(c.MaxClientBufferMiB)<<20) {
		return r
	}
	if b.pending >= maxPendingAdmissions || b.pendingApps[id] >= maxPendingPerApplication || b.pendingClients[key] {
		b.waitCapacityRefused++
		return r
	}
	if b.pendingApps == nil {
		b.pendingApps = map[string]int{}
	}
	if b.pendingClients == nil {
		b.pendingClients = map[pendingClient]bool{}
	}
	b.pending++
	b.waitEntered++
	b.pendingApps[id]++
	b.pendingClients[key] = true
	queued = true
	if b.changed == nil {
		b.changed = make(chan struct{})
	}
	epoch := b.admissionEpoch
	deadline := time.Now().Add(time.Duration(c.AdmissionWaitMS) * time.Millisecond)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
		case <-ctx.Done():
		}
		b.mu.Lock()
		if ctx.Err() != nil {
			b.waitCancelled++
			r = admissionResult{status: 503, reason: "Admission cancelled", retry: 1}
			return r
		}
		if epoch != b.admissionEpoch {
			b.waitPolicyChanged++
			r = admissionResult{status: 503, reason: "Policy changed during admission", retry: 1}
			return r
		}
		if !time.Now().Before(deadline) {
			b.waitExpired++
			return r
		}
		r = b.tryAdmitLocked(id, ip, weight, c, applications, time.Now())
		// A busy client cannot head-of-line block other eligible clients.
		// Rate refusals never wait or consume a token.
		if r.status != 503 {
			if r.status == 0 {
				b.waitAdmitted++
			} else {
				b.waitRateRefused++
			}
			return r
		}
	}
}

func (b *resourceBudget) signalAdmissionLocked() {
	if b.changed != nil {
		close(b.changed)
		b.changed = nil
		if b.pending > 0 {
			b.changed = make(chan struct{})
		}
	}
}

func (b *resourceBudget) tryAdmitLocked(id, ip string, weight int64, c TrafficControls, applications int, now time.Time) admissionResult {
	if b.applications == nil {
		b.applications = map[string]*applicationBudget{}
	}
	a := b.applications[id]
	if a == nil {
		a = &applicationBudget{clients: map[string]*clientBudget{}}
		b.applications[id] = a
	}
	concurrency := b.limits.MaxConcurrent / applications
	if c.MaxConcurrent > 0 {
		concurrency = min(concurrency, c.MaxConcurrent)
	}
	if a.active >= concurrency || weight > b.limits.BufferBytes/int64(applications)-a.reserved || b.active >= b.limits.MaxConcurrent || weight > b.limits.BufferBytes-b.reserved {
		return admissionResult{status: 503, reason: "Application admission share exhausted", retry: 1}
	}
	var client *clientBudget
	if c.ClientRequestsPerSecond > 0 || c.MaxClientConcurrent > 0 || c.MaxClientBufferMiB > 0 || c.ClientBodyKiBPerSecond > 0 {
		client = a.clients[ip]
		if client == nil {
			// Examine at most sixteen old entries per admission, even under churn.
			for element, scanned := a.recent.Front(), 0; element != nil && scanned < 16; scanned++ {
				next := element.Next()
				old := element.Value.(*clientBudget)
				if old.active == 0 && now.Sub(old.seen) >= 10*time.Minute {
					delete(a.clients, old.key)
					a.recent.Remove(element)
				}
				element = next
			}
			if len(a.clients) >= maxClientBuckets {
				return admissionResult{status: 429, reason: "Application client tracking capacity exhausted", retry: 600}
			}
			client = &clientBudget{key: ip}
			client.element = a.recent.PushBack(client)
			a.clients[ip] = client
		}
		client.seen = now
		a.recent.MoveToBack(client.element)
		if c.MaxClientConcurrent > 0 && client.active >= c.MaxClientConcurrent {
			return admissionResult{status: 503, reason: "Client concurrency share exhausted", retry: 1}
		}
		if c.MaxClientBufferMiB > 0 && weight > (int64(c.MaxClientBufferMiB)<<20)-client.reserved {
			return admissionResult{status: 503, reason: "Client buffer share exhausted", retry: 1}
		}
		client.bucket.refill(now, c.ClientRequestsPerSecond, c.ClientBurst)
		client.bodyBucket.refill(now, c.ClientBodyKiBPerSecond, c.ClientBodyBurstKiB)
		client.refillBodyReservation(now, c)
	}
	a.bucket.refill(now, c.RequestsPerSecond, c.Burst)
	retry := a.bucket.retry()
	if client != nil {
		retry = max(retry, client.bucket.retry())
		bodyRetry := client.bodyBucket.retryCost(float64(c.bodyKiB))
		if lane := client.bodyLane(c); lane != nil {
			bodyRetry = max(bodyRetry, lane.retryCost(float64(c.bodyKiB)))
		}
		if bodyRetry > 0 {
			return admissionResult{status: 429, reason: "Client request body rate exceeded", retry: max(retry, bodyRetry)}
		}
	}
	if retry > 0 {
		return admissionResult{status: 429, reason: "Application or client request rate exceeded", retry: retry}
	}
	if c.RequestsPerSecond > 0 {
		a.bucket.tokens--
	}
	if client != nil {
		if c.ClientRequestsPerSecond > 0 {
			client.bucket.tokens--
		}
		if c.ClientBodyKiBPerSecond > 0 {
			client.bodyBucket.tokens -= float64(c.bodyKiB)
			if lane := client.bodyLane(c); lane != nil {
				lane.tokens -= float64(c.bodyKiB)
			}
		}
		client.active++
		client.reserved += weight
	}
	a.active++
	a.reserved += weight
	b.active++
	b.reserved += weight
	return admissionResult{release: func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		a.active--
		a.reserved -= weight
		b.active--
		b.reserved -= weight
		if client != nil {
			client.active--
			client.reserved -= weight
		}
		if a.retired && a.active == 0 && b.applications[id] == a {
			delete(b.applications, id)
		}
		b.signalAdmissionLocked()
	}}
}

func (b *resourceBudget) configureApplications(c Config) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.admissionEpoch++
	b.signalAdmissionLocked()
	keep := map[string]bool{}
	for _, app := range c.Applications {
		keep[app.ApplicationID] = true
	}
	for id, app := range b.applications {
		app.retired = !keep[id]
		if !keep[id] && app.active == 0 {
			delete(b.applications, id)
		}
	}
	if b.applications == nil {
		b.applications = map[string]*applicationBudget{}
	}
	now := time.Now()
	for _, app := range c.Applications {
		state := b.applications[app.ApplicationID]
		if state == nil {
			state = &applicationBudget{clients: map[string]*clientBudget{}}
			b.applications[app.ApplicationID] = state
		}
		state.retired = false
		controls := TrafficControls{}
		if app.TrafficControls != nil {
			controls = *app.TrafficControls
		}
		state.bucket.refill(now, controls.RequestsPerSecond, controls.Burst)
		for _, client := range state.clients {
			client.bucket.refill(now, controls.ClientRequestsPerSecond, controls.ClientBurst)
			client.bodyBucket.refill(now, controls.ClientBodyKiBPerSecond, controls.ClientBodyBurstKiB)
			client.refillBodyReservation(now, controls)
		}
	}
}

func validateAdmissionShares(c Config, limits ResourceLimits) error {
	if c.SchemaVersion == 2 && len(c.Applications) > limits.MaxConcurrent {
		return errors.New("process concurrency must provide at least one slot per application")
	}
	return nil
}
