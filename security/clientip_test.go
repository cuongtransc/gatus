package security

import (
	"net"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	_, internal, _ := net.ParseCIDR("10.0.0.0/8")
	scenarios := []struct {
		Name     string
		Peer     string
		Header   string
		Trusted  []*net.IPNet
		Expected string
	}{
		{Name: "cloudflare-peer-valid-header", Peer: "173.245.48.1", Header: "203.0.113.7", Expected: "203.0.113.7"},
		{Name: "cloudflare-peer-header-with-spaces", Peer: "104.16.0.1", Header: " 203.0.113.7 ", Expected: "203.0.113.7"},
		{Name: "cloudflare-peer-garbage-header", Peer: "173.245.48.1", Header: "garbage", Expected: "173.245.48.1"},
		{Name: "cloudflare-peer-no-header", Peer: "173.245.48.1", Header: "", Expected: "173.245.48.1"},
		{Name: "non-cloudflare-peer-header-ignored", Peer: "203.0.113.9", Header: "198.51.100.1", Expected: "203.0.113.9"},
		{Name: "trusted-proxy-peer", Peer: "10.1.2.3", Header: "198.51.100.1", Trusted: []*net.IPNet{internal}, Expected: "198.51.100.1"},
		{Name: "untrusted-private-peer", Peer: "10.1.2.3", Header: "198.51.100.1", Expected: "10.1.2.3"},
		{Name: "cloudflare-ipv6-peer", Peer: "2606:4700::1", Header: "2001:db8::1", Expected: "2001:db8::1"},
		{Name: "ipv4-mapped-cloudflare-peer", Peer: "::ffff:173.245.48.1", Header: "203.0.113.7", Expected: "203.0.113.7"},
		{Name: "header-normalised", Peer: "173.245.48.1", Header: "2001:DB8:0:0::1", Expected: "2001:db8::1"},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			actual := resolveClientIP(net.ParseIP(scenario.Peer), scenario.Header, scenario.Trusted)
			if actual != scenario.Expected {
				t.Errorf("expected %s, got %s", scenario.Expected, actual)
			}
		})
	}
}
