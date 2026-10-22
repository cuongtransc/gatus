package security

import (
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// cloudflareCIDRs are Cloudflare's published proxy ranges.
// Source: https://www.cloudflare.com/ips/ (refresh by hand).
var cloudflareCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var cloudflareNets = parseCIDRs(cloudflareCIDRs)

func parseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("security: invalid built-in CIDR " + cidr + ": " + err.Error())
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// isTrustedProxy returns whether peer is a Cloudflare address or inside one of the trusted networks
func isTrustedProxy(peer net.IP, trusted []*net.IPNet) bool {
	for _, n := range cloudflareNets {
		if n.Contains(peer) {
			return true
		}
	}
	for _, n := range trusted {
		if n.Contains(peer) {
			return true
		}
	}
	return false
}

// resolveClientIP returns the CF-Connecting-IP value if the peer is a trusted proxy and the value is a valid IP,
// otherwise the peer address itself
func resolveClientIP(peer net.IP, cfConnectingIP string, trusted []*net.IPNet) string {
	if isTrustedProxy(peer, trusted) {
		if ip := net.ParseIP(strings.TrimSpace(cfConnectingIP)); ip != nil {
			return ip.String()
		}
	}
	return peer.String()
}

// clientIP returns the IP of the client that issued the request
func (c *Config) clientIP(ctx *fiber.Ctx) string {
	return resolveClientIP(ctx.Context().RemoteIP(), ctx.Get("CF-Connecting-IP"), c.trustedNets())
}

func (c *Config) trustedNets() []*net.IPNet {
	if c.BruteForce == nil {
		return nil
	}
	return c.BruteForce.trustedNets
}
