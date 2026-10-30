package transport

import (
	"math"
	"sync"
	"time"

	"lancollab/internal/protocol"
)

// CUBIC constants (RFC 8312): C scales the curve, beta is the decrease factor on loss.
const (
	cubicC    = 0.4
	cubicBeta = 0.7
)

// CubicController keeps one peer's cwnd: slow start below ssthresh, the CUBIC curve above, x0.7 on loss.
type CubicController struct {
	mu         sync.Mutex
	cwnd       float64
	ssthresh   float64
	maxWin     float64
	wMax       float64
	k          float64
	epochStart time.Time
	now        func() time.Time
}

// NewCubicController returns a controller with cwnd = 4, ssthresh = 16, max window 64.
func NewCubicController() *CubicController {
	return &CubicController{
		cwnd:     protocol.InitialCwnd,
		ssthresh: protocol.InitialSsthresh,
		maxWin:   protocol.MaxCwnd,
		now:      time.Now,
	}
}

// OnAck grows the window for one newly acknowledged packet.
func (c *CubicController) OnAck() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cwnd < c.ssthresh {
		c.cwnd++ // Slow Start
	} else {
		now := c.now()
		if c.epochStart.IsZero() {
			// Entered congestion avoidance without a loss yet: start a new epoch at the current window.
			c.epochStart = now
			if c.wMax < c.cwnd {
				c.wMax = c.cwnd
				c.k = 0
			} else {
				c.k = math.Cbrt(c.wMax * (1 - cubicBeta) / cubicC)
			}
		}
		t := now.Sub(c.epochStart).Seconds()
		d := t - c.k
		target := cubicC*d*d*d + c.wMax
		if target > c.cwnd {
			c.cwnd += (target - c.cwnd) / c.cwnd
		} else {
			c.cwnd += 0.01 / c.cwnd // gentle probing on the plateau
		}
	}
	if c.cwnd > c.maxWin {
		c.cwnd = c.maxWin
	}
}

// OnLoss applies the multiplicative decrease after a retransmission timeout.
func (c *CubicController) OnLoss() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wMax = c.cwnd
	c.ssthresh = math.Max(2.0, c.cwnd*cubicBeta)
	c.cwnd = c.ssthresh
	c.k = math.Cbrt(c.wMax * (1 - cubicBeta) / cubicC)
	c.epochStart = c.now()
}

// EffectiveWindow returns min(cwnd, peerRwnd), at least 1 so a zero window still allows a probe.
func (c *CubicController) EffectiveWindow(peerRwnd uint8) int {
	c.mu.Lock()
	w := int(c.cwnd)
	c.mu.Unlock()
	if r := int(peerRwnd); r < w {
		w = r
	}
	if w < 1 {
		w = 1
	}
	return w
}

// Cwnd returns the current congestion window in packets.
func (c *CubicController) Cwnd() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cwnd
}

// Ssthresh returns the current slow-start threshold in packets.
func (c *CubicController) Ssthresh() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ssthresh
}
