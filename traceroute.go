package traceroute

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/Sirupsen/logrus"
)

func tracerouteProbe(opts *TracerouteOptions, ttl int, timeout *syscall.Timeval) ProbeResponse {
	start := time.Now()

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
	syscall.SetsockoptTimeval(sendSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, timeout)
	// set option to tell the kernel to give us errors when we call recvmsg
	err = syscall.SetsockoptInt(sendSocket, syscall.SOL_IP, syscall.IP_RECVERR, 1)
	if err != nil {
		logrus.Errorf("error IP_RECVERR: %v", err)
	}

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

	var currIP net.IP

	// attempt to get errors?
	end := time.Now().Add(time.Second)
	// TODO: goroutine? something cancellable
	for {
		now := time.Now()
		if now.After(end) {
			break
		}

		// golang creates all sockets as nonblocking. Although we *should* be able
		// to use syscall.SetNonblock(sendSocket, false) -- it doesn't seem to work
		// for some reason (presumably due to the magic that makes it nonblocking)
		// instead of spinning for days-- we can epoll on it (for some reason select
		// isn't working, presumably it doesn't have the correct magic).
		epollfd, err := syscall.EpollCreate(1)
		defer syscall.Close(epollfd)
		epollevent := syscall.EpollEvent{}
		err = syscall.EpollCtl(epollfd, syscall.EPOLL_CTL_ADD, sendSocket, &epollevent)
		syscall.EpollWait(epollfd, []syscall.EpollEvent{epollevent}, int(end.Sub(now).Nanoseconds() / int64(time.Millisecond)))

		var p = make([]byte, 1500)   // TODO: configurable recv size?
		var oob = make([]byte, 1500) // TODO: configurable recv size?
		_, oobn, _, _, err := syscall.Recvmsg(sendSocket, p, oob, syscall.MSG_ERRQUEUE)
		if err != nil || oobn <= 0 {
			continue
		}

		// TODO: cleanup this parsing? Right now these structs aren't really well
		// APId, so we end up having to do a fair amount of magic. I'll do my best
		// to document the magic for now

		// The beginning of the oob is a cmsghdr, so we need to load that
		cmsghdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
		// If this isn't an IP level message, skip it
		if cmsghdr.Level != syscall.IPPROTO_IP {
			continue
		}

		// After the cmsghdr is a SockExtendedErr, so we do similar things
		se := (*SockExtendedErr)(unsafe.Pointer(&oob[syscall.SizeofCmsghdr]))

		// If the message isn't from ICMP-- skip (TODO: not a magic number here!
		// Number taken from http://lxr.free-electrons.com/source/include/uapi/linux/errqueue.h#L18
		if se.Origin != 2 {
			continue
		}

		// Switch on the msg type
		// we are expecting an ICMPTypeTimeExceeded
		switch cmsghdr.Type {
		case int32(ipv4.ICMPTypeTimeExceeded):
			src := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&oob[syscall.SizeofCmsghdr+int(unsafe.Sizeof(*se))]))
			currIP = sockAddrToIP(&syscall.SockaddrInet4{Port: int(src.Port), Addr: src.Addr})
		case int32(ipv6.ICMPTypeTimeExceeded):
			src := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&oob[syscall.SizeofCmsghdr+int(unsafe.Sizeof(*se))]))
			currIP = sockAddrToIP(&syscall.SockaddrInet6{Port: int(src.Port), Addr: src.Addr})
		}
		break
	}

	elapsed := time.Since(start)
	if currIP == nil {
		return ProbeResponse{Success: false, Error: fmt.Errorf("Probe timeout"), TTL: ttl}
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
