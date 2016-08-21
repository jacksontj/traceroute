// TODO: most of this probably could go into a more generic ICMP package
package traceroute

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Determine if the embedded L3 headers match
// if so return the L4 protocol number, buffer, and error
func matchICMP(message *icmp.Message, opts *TracerouteOptions) (int, []byte, error) {
	switch t := message.Body.(type) {
	case *icmp.TimeExceeded:
		switch message.Type.Protocol() {
		case ProtocolICMP:
			ipHeader, err := ipv4.ParseHeader(t.Data)
			if err != nil {
				return -1, nil, err
			}
			// Verify that the destination address is the same
			if ipHeader.Dst.Equal(opts.DestinationAddr) {
				return ipHeader.Protocol, t.Data[ipHeader.Len : ipHeader.TotalLen-1], nil

			}
		// TODO: implement to support ipv6
		case ProtocolIPv6ICMP:
			return -1, nil, fmt.Errorf("IPv6 ICMP not implemented yet")
		}

	}
	logrus.Debugf("unable to match ICMP message")
	return -1, nil, nil
}

// TODO: better, this is a decent amount of magic... curse you ICMP!!!
// TODO: with timeout
// recieve on ICMP socket until you get a message which was destined for our TracerouteOptions
func recvICMP(recvSocket int, opts *TracerouteOptions) (net.IP, error) {
	end := time.Now().Add(opts.ProbeTimeout)
	for {
		if time.Now().After(end) {
			return nil, fmt.Errorf("hit probeTimeout")
		}
		var p = make([]byte, 1500) // TODO: configurable recv size?
		n, from, err := syscall.Recvfrom(recvSocket, p, 0)
		// if the error was temporarily unavailable, we should retry to a timeout
		if err != nil {
			continue
		}
		// if we didn't recieve any bytes, go again
		if n <= 20 {
			continue
		}

		var hopIP net.IP
		var icmpProto int
		var headerLen int
		// We need to know the ip version to load the L3 header, we'll determine this
		// from the socket type
		switch from.(type) {
		case *syscall.SockaddrInet4:
			ipHeader, err := ipv4.ParseHeader(p[0:ipv4.HeaderLen])
			if err != nil {
				continue
			}
			// move our pointer-- we already read that header
			hopIP = ipHeader.Src
			icmpProto = ProtocolICMP
			headerLen = ipHeader.Len
		case *syscall.SockaddrInet6:
			icmpProto = ProtocolIPv6ICMP
		}
		// Now that we have parsed out what proto this is, and who sent us the packet,
		// we need to open up the ICMP message itself-- which is the remainder of the
		// response
		message, err := icmp.ParseMessage(icmpProto, p[headerLen:n])
		// If the ICMP message is bad, go again
		if err != nil {
			continue
		}
		// Now that we have an ICMP message, lets determine see if it matches
		l4Protocol, l4Buffer, err := matchICMP(message, opts)
		// If the L3 headers didn't match go again
		if err != nil || l4Protocol == -1 {
			continue
		}

		var l4header L4Header
		// TODO: implement other L4protocols here
		switch l4Protocol {
		case ProtocolUDP:
			l4header = &UDPHeader{}
			err := binary.Read(
				bytes.NewReader(l4Buffer),
				binary.BigEndian,
				l4header,
			)
			// TODO: this?
			if err != nil {
				continue
			}
		}

		if l4header.SrcPort() == opts.SourcePort && l4header.DstPort() == opts.DestinationPort {
			return hopIP, nil
		}
	}
}
