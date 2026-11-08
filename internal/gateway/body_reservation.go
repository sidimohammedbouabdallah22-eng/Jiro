package gateway

import (
	"errors"
	"net/url"
	"path"
	"strings"
	"time"
)

// BodyReservation partitions the client byte budget for one operator-selected
// route. It grants no authentication or inspection exemption. Both partitions
// also consume the original aggregate bucket under the admission mutex.
type BodyReservation struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	KiBPerSecond int    `json:"kib_per_second"`
	BurstKiB     int    `json:"burst_kib"`
}

func (c TrafficControls) validateBodyReservation() error {
	r := c.ClientBodyReservation
	if r == nil {
		return nil
	}
	if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" {
		return errors.New("body reservation method must be POST, PUT or PATCH")
	}
	u, err := url.ParseRequestURI(r.Path)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || r.Path != u.EscapedPath() || strings.ContainsAny(r.Path, "%?#\\") || !strings.HasPrefix(r.Path, "/") || path.Clean(r.Path) != r.Path || len(r.Path) > 512 {
		return errors.New("body reservation requires an exact canonical unescaped path of at most 512 bytes")
	}
	if r.KiBPerSecond <= 0 || r.KiBPerSecond >= c.ClientBodyKiBPerSecond || r.BurstKiB <= 0 || r.BurstKiB >= c.ClientBodyBurstKiB || int64(r.BurstKiB) > int64(r.KiBPerSecond)*600 || int64(c.ClientBodyBurstKiB-r.BurstKiB) > int64(c.ClientBodyKiBPerSecond-r.KiBPerSecond)*600 {
		return errors.New("body reservation must leave positive bounded rate and burst for both partitions")
	}
	return nil
}

func (client *clientBudget) refillBodyReservation(now time.Time, c TrafficControls) {
	reservedRate, reservedBurst := 0, 0
	if r := c.ClientBodyReservation; r != nil {
		reservedRate, reservedBurst = r.KiBPerSecond, r.BurstKiB
	}
	client.reservedBodyBucket.refill(now, reservedRate, reservedBurst)
	client.generalBodyBucket.refill(now, c.ClientBodyKiBPerSecond-reservedRate, c.ClientBodyBurstKiB-reservedBurst)
}

func (client *clientBudget) bodyLane(c TrafficControls) *tokenBucket {
	if c.ClientBodyReservation == nil {
		return nil
	}
	if c.reservedBody {
		return &client.reservedBodyBucket
	}
	return &client.generalBodyBucket
}
