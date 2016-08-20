package traceroute

import (
	"net"
	"syscall"
	"time"
)

type probeType uint8

const (
	udpProbe probeType = iota
	tcpProbe
	icmpProbe
)

// TODO: size of packet to send
type TracerouteOptions struct {
	SourceAddr     net.IP
	SourcePort     int
	sourceSockaddr syscall.Sockaddr

	DestinationAddr net.IP
	DestinationPort int
	destSockaddr    syscall.Sockaddr

	// enumerated value of tcp/udp/icmp
	ProbeType probeType // TODO: make the enum

	// TTL options
	StartingTTL int // default to 1
	MaxTTL      int // default to 30

	// Probe options
	ProbeTimeout time.Duration // timeout for a probe -- default 5
	ProbeCount   int           // Number of probes per hop-- default to 3
	ProbeWait    time.Duration // time to wait between probes -- default 0

	// TODO
	//ProbeConcurrency int           // default to 1

	// TODO: support both, ipv4, ipv6 (perferably with a preference order)
	//IPVersion ipVersion // TODO: make the enum

	// TODO
	// Result options
	// don't resolve IP -> name
}
