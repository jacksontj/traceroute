package traceroute

import (
	"net"
	"time"
)

type ProbeResponse struct {
	Success      bool
	Error        error
	Address      net.IP
	Duration     time.Duration
	TTL          int
	ResponseSize int
}

type Hop struct {
	Responses []ProbeResponse
}

// TracerouteResult type
type TracerouteResult struct {
	Opts *TracerouteOptions
	Hops []Hop
}
