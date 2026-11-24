package unifi

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// A cooldown belongs to one configured controller client. The latest deadline
// wins when several in-flight requests report different throttle windows.
type readCooldown struct {
	mu    sync.Mutex
	until time.Time
}

func (g *readCooldown) extend(delay time.Duration) {
	until := time.Now().Add(delay)
	g.mu.Lock()
	defer g.mu.Unlock()
	if until.After(g.until) {
		g.until = until
	}
}

func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func (g *readCooldown) beforeRead(req *http.Request) error {
	if !isReadMethod(req.Method) {
		return nil
	}
	for {
		g.mu.Lock()
		remaining := time.Until(g.until)
		g.mu.Unlock()
		if remaining <= 0 {
			return req.Context().Err()
		}
		timer := time.NewTimer(remaining)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return req.Context().Err()
		case <-timer.C:
			// Another response may have extended the cooldown while we waited.
		}
	}
}

func readRetryDelay(minWait, maxWait time.Duration, attempt int, resp *http.Response) time.Duration {
	if delay, ok := parseRetryAfter(resp); ok {
		return min(delay, maxWait)
	}
	return retryablehttp.DefaultBackoff(minWait, maxWait, attempt, nil)
}

// The boolean distinguishes an explicit zero delay from an absent or invalid
// header. Saturate oversized delta-seconds before converting them to Duration.
func parseRetryAfter(resp *http.Response) (time.Duration, bool) {
	v := resp.Header.Get("Retry-After")
	if secs, err := strconv.ParseUint(v, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		if secs > uint64(math.MaxInt64/int64(time.Second)) {
			return time.Duration(math.MaxInt64), true
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0), true
	}
	return 0, false
}
