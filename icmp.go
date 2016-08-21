// TODO: most of this probably could go into a more generic ICMP package
package traceroute

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Determine if the L3 headers match, if so return the L4 protocol number, the buffer, and an error if one exists
func matchICMP(message *icmp.Message, opts *TracerouteOptions) (int, []byte, error) {
	switch t := message.Body.(type) {
	case *icmp.TimeExceeded:
		switch message.Type.Protocol() {
		case ProtocolICMP:
			ipHeader, err := ipv4.ParseHeader(t.Data)
			if err != nil {
				return 0, nil, err
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
// recieve on ICMP socket until you get a message which was destined for dstIP
func recvICMP(recvSocket int, opts *TracerouteOptions) (syscall.Sockaddr, error) {
	end := time.Now().Add(opts.ProbeTimeout)
	for {
		if time.Now().After(end) {
			return nil, fmt.Errorf("hit probeTimeout")
		}
		var p = make([]byte, 1500) // TODO: configurable recv size?
		n, from, err := syscall.Recvfrom(recvSocket, p, 0)
		// if the error was temporarily unavailable, we should retry to a timeout
		if err != nil {
			if !time.Now().After(end) {
				continue
			}
			return nil, err
		}
		// if we didn't recieve any bytes, go again
		if n <= 0 {
			continue
		}

		// We need to know the ip version to load the ICMP message, so we'll
		// switch on the destination address
		var icmpProto int
		switch from.(type) {
		case *syscall.SockaddrInet4:
			icmpProto = ProtocolICMP
		case *syscall.SockaddrInet6:
			icmpProto = ProtocolIPv6ICMP
		}
		// TODO: for some reason RecvFrom is giving us the IP header as well-- so we'll
		// just skip the first 20 bytes and move on with our lives
		message, err := icmp.ParseMessage(icmpProto, p[20:n])
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
			return from, nil
		}
	}
}
