package traceroute

import (
	"fmt"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
)

func tracerouteProbe(opts *TracerouteOptions, ttl int, timeout *syscall.Timeval) ProbeResponse {
	start := time.Now()

	// Set up an ICMP socket to get the TTL expired messages
	recvSocket, err := syscall.Socket(
		syscall.AF_INET,
		syscall.SOCK_RAW,
		syscall.IPPROTO_ICMP,
	)
	if err != nil {
		return ProbeResponse{Success: false, Error: err, TTL: ttl}
	}
	defer syscall.Close(recvSocket)

	// Set up the socket to send packets out on
	// TODO: switch on probeType
	sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return ProbeResponse{Success: false, Error: err, TTL: ttl}
	}

	defer syscall.Close(sendSocket)

	// Set the TTL on the sendSocket
	syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
	// Set a timeout on the send socket (so we don't wait forever)
	syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, timeout)

	// Bind to the local socket to listen for ICMP packets
	syscall.Bind(recvSocket, opts.sourceSockaddr)

	if opts.SourcePort > 0 {
		// if srcPort is set, bind to that as well
		syscall.SetsockoptInt(sendSocket, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		err = syscall.Bind(sendSocket, opts.sourceSockaddr)
		// TODO: non-fatal error
		if err != nil {
			return ProbeResponse{Success: false, Error: err, TTL: ttl}
		}
	}

	// TODO: switch based on proto
	// TODO: send some actual bytes based on opts
	// Send a single null byte packet
	syscall.Sendto(sendSocket, []byte{0x0}, 0, opts.destSockaddr)

	currIP, err := recvICMP(recvSocket, opts)
	elapsed := time.Since(start)
	if err != nil {
		return ProbeResponse{Success: false, Error: err, TTL: ttl}
	} else {
		return ProbeResponse{
			Success: true,
			Address: currIP,
			// TODO: even helpful?
			//ResponseSize: n,
			Duration: elapsed,
			TTL:      ttl,
		}
	}
}

// Main traceroute method, we take in a set of options, and do a traceroute
func Traceroute(opts *TracerouteOptions) (TracerouteResult, error) {
	logrus.Debugf("doing a traceroute: %v", opts)

	if opts.ResultChan != nil {
		defer close(opts.ResultChan)
	}

	result := TracerouteResult{
		Opts: opts,
		Hops: make([]Hop, 0),
	}

	// Convert the net.IPs to the appropriate sockaddrs
	opts.sourceSockaddr = ipPortToSockaddr(opts.SourceAddr, opts.SourcePort)
	opts.destSockaddr = ipPortToSockaddr(opts.DestinationAddr, opts.DestinationPort)

	timeout := syscall.NsecToTimeval(opts.ProbeTimeout.Nanoseconds())
	ttl := opts.StartingTTL

	for {
		responses := make([]ProbeResponse, 0)

		finalDestination := true
		for x := 0; x < opts.ProbeCount; x++ {
			probeResponse := tracerouteProbe(opts, ttl, &timeout)
			logrus.Debugf("Probe %d: %v", ttl, probeResponse)
			// TODO: nonblocking?
			if opts.ResultChan != nil {
				opts.ResultChan <- &probeResponse
			}
			responses = append(responses, probeResponse)
			finalDestination = finalDestination && probeResponse.Address.Equal(opts.DestinationAddr)
		}
		result.Hops = append(result.Hops, Hop{responses})
		// If we are at our final destination, then we are done!
		if finalDestination {
			return result, nil
		}

		// If we hit our max TTL, then we are also done
		if ttl >= opts.MaxTTL {
			return result, fmt.Errorf("Hit max TTL before getting to destination")
		}

		// We finished this TTL, lets increment and then do our sleep
		ttl++

		// sleep between hops however much we where asked to
		time.Sleep(opts.ProbeWait)

	}

	return result, nil
}
