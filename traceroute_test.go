package traceroute

import (
	"net"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
)

func getOptions() *TracerouteOptions {
	ip, err := GetLocalIP()
	if err != nil {
		logrus.Fatalf("Unable to get a local IP for testing: %v", err)
	}
	dstIPs, err := net.LookupIP("www.google.com")
	if err != nil {
		logrus.Fatalf("Unable to resolve www.google.com for a destination: %v", err)
	}
	return &TracerouteOptions{
		SourceAddr: ip,
		SourcePort: 34456,

		DestinationAddr: dstIPs[0],
		DestinationPort: 80,

		// enumerated value of tcp/udp/icmp
		ProbeType: UdpProbe,

		// TTL options
		StartingTTL: 1,
		MaxTTL:      30,

		// Probe options
		ProbeTimeout: time.Second,
		ProbeCount:   1,
		//ProbeWait: 0,
		//ProbeConcurrency: 1,

		//IPVersion ipVersion // TODO: make the enum

		// TODO
		// Result options
		// don't resolve IP -> name
	}
}

func TestTraceroute(t *testing.T) {

	result, err := Traceroute(getOptions())

	if err != nil {
		t.Error("Error tracerouting: %v", err)
	}

	if len(result.Hops) > result.Opts.MaxTTL {
		t.Error("Traceroute exceeded MaxTTL!")
	}
	logrus.Infof("Result: %v", result)
}
