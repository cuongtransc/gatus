package security

import (
	"net"
	"time"
)

const (
	// DefaultBruteForceMaxAttempts is the default number of failed attempts allowed within the window
	DefaultBruteForceMaxAttempts = 5
	// DefaultBruteForceWindow is the default period in which failed attempts are counted
	DefaultBruteForceWindow = 15 * time.Minute
	// DefaultBruteForceBlockDuration is the default duration an IP stays blocked
	DefaultBruteForceBlockDuration = 30 * time.Minute
)

// BruteForceConfig is the configuration for blocking IPs that fail to log in too many times
type BruteForceConfig struct {
	// MaxAttempts is the number of failed attempts within Window after which the IP is blocked
	MaxAttempts int `yaml:"max-attempts,omitempty"`

	// Window is the period in which failed attempts are counted
	Window time.Duration `yaml:"window,omitempty"`

	// BlockDuration is how long an IP stays blocked
	BlockDuration time.Duration `yaml:"block-duration,omitempty"`

	// TrustedProxies is a list of IPs/CIDRs whose forwarding headers are trusted to resolve the client IP
	TrustedProxies []string `yaml:"trusted-proxies,omitempty"`

	trustedNets []*net.IPNet
}

// ValidateAndSetDefaults returns whether the configuration is valid and sets default values.
// A zero value means "use the default"; a negative value is invalid.
func (c *BruteForceConfig) ValidateAndSetDefaults() bool {
	if c.MaxAttempts < 0 || c.Window < 0 || c.BlockDuration < 0 {
		return false
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = DefaultBruteForceMaxAttempts
	}
	if c.Window == 0 {
		c.Window = DefaultBruteForceWindow
	}
	if c.BlockDuration == 0 {
		c.BlockDuration = DefaultBruteForceBlockDuration
	}
	// Rebuilt from scratch on every call so that hot reloads don't accumulate entries
	c.trustedNets = nil
	for _, entry := range c.TrustedProxies {
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			c.trustedNets = append(c.trustedNets, ipNet)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return false
		}
		bits := 128
		if ip4 := ip.To4(); ip4 != nil {
			ip, bits = ip4, 32
		}
		c.trustedNets = append(c.trustedNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return true
}
