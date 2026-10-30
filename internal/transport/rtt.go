// Package transport has the TLS control channel and the reliable UDP engine (SR, RTT, rwnd, CUBIC, no HoL).
package transport

import (
	"sync"
	"time"

	"lancollab/internal/protocol"
)

// EWMA weights recommended by Kurose & Ross §3.5.3 and RFC 6298.
const (
	rttAlpha = 0.125 // weight of a new SampleRTT in EstimatedRTT
	rttBeta  = 0.25  // weight of a new deviation in DevRTT
)

// RTTEstimator follows Kurose 3.5.3: EWMA RTT and DevRTT, RTO = EstRTT + 4*DevRTT clamped to 50 ms..2 s.
type RTTEstimator struct {
	mu        sync.Mutex
	estimated time.Duration
	dev       time.Duration
	rto       time.Duration
	hasSample bool
}

// NewRTTEstimator returns an estimator with the initial values above.
func NewRTTEstimator() *RTTEstimator {
	return &RTTEstimator{
		estimated: 100 * time.Millisecond,
		dev:       50 * time.Millisecond,
		rto:       protocol.InitialRTO,
	}
}

// Update feeds one SampleRTT; samples from retransmitted packets are ignored (Karn's rule).
func (r *RTTEstimator) Update(sample time.Duration, isRetransmitted bool) {
	if isRetransmitted || sample < 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.hasSample {
		r.estimated = sample
		r.dev = sample / 2
		r.hasSample = true
	} else {
		r.estimated = time.Duration((1-rttAlpha)*float64(r.estimated) + rttAlpha*float64(sample))
		diff := sample - r.estimated
		if diff < 0 {
			diff = -diff
		}
		r.dev = time.Duration((1-rttBeta)*float64(r.dev) + rttBeta*float64(diff))
	}
	// A fresh measurement also cancels any exponential backoff applied by OnTimeout.
	r.rto = clampRTO(r.estimated + 4*r.dev)
}

// OnTimeout doubles the timeout interval (exponential backoff), up to 2000 ms.
func (r *RTTEstimator) OnTimeout() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rto = clampRTO(2 * r.rto)
}

// RTO returns the current timeout interval.
func (r *RTTEstimator) RTO() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rto
}

// EstimatedRTT returns the smoothed RTT.
func (r *RTTEstimator) EstimatedRTT() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.estimated
}

// DevRTT returns the RTT deviation estimate.
func (r *RTTEstimator) DevRTT() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dev
}

func clampRTO(d time.Duration) time.Duration {
	if d < protocol.MinRTO {
		return protocol.MinRTO
	}
	if d > protocol.MaxRTO {
		return protocol.MaxRTO
	}
	return d
}
