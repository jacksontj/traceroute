// TODO: most of this probably could go into a more generic ICMP package
package traceroute

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Determine if the L3 headers match, if so return the L4 protocol number, the buffer, and an error if one exists
func matchICMP4(message *icmp.Message, opts *TracerouteOptions) (int, []byte, error) {
	switch t := message.Body.(type) {
	case *icmp.TimeExceeded:
		//logrus.Infof("time exceeded message! %v", t.Data)
		ipHeader, err := ipv4.ParseHeader(t.Data)
		if err != nil {
			return 0, nil, err
		}
		//logrus.Infof("ipheader: %v", ipHeader)
		// Verify that the destination address is the same
		if ipHeader.Dst.Equal(opts.DestinationAddr) {
			return ipHeader.Protocol, t.Data[ipHeader.Len : ipHeader.TotalLen-1], nil

		}

	}
	logrus.Debugf("unable to match ICMP message")
	return -1, nil, nil
}

// TODO: implement
func matchICMP6(message *icmp.Message, opts *TracerouteOptions) (L4Header, error) {
	return nil, fmt.Errorf("ipv6 ICMP magic not implemented")
}

// TODO: support ipv6
// TODO: better, this is a decent amount of magic... curse you ICMP!!!
// TODO: with timeout
// recieve on ICMP socket until you get a message which was destined for dstIP
func recvICMP(recvSocket int, opts *TracerouteOptions) (syscall.Sockaddr, error) {
	for {
		var p = make([]byte, 1500) // TODO: configurable recv size?
		n, from, err := syscall.Recvfrom(recvSocket, p, 0)
		// if the error was temporarily unavailable, we should retry to a timeout
		if err != nil {
			return nil, err
		}
		if n > 0 {

			var icmpProto int
			switch from.(type) {
			case *syscall.SockaddrInet4:
				icmpProto = ProtocolICMP
			case *syscall.SockaddrInet6:
				icmpProto = ProtocolIPv6ICMP
			}
			// TODO: for some reason RecvFrom is giving us the IP header as well-- so we'll
			// just skip the first 20 bytes and move on with our lives
			message, err := icmp.ParseMessage(icmpProto, p[0:n][20:])
			if err != nil {
				return nil, err
			}
			var l4Protocol int
			var l4Buffer []byte
			switch from.(type) {
			case *syscall.SockaddrInet4:
				l4Protocol, l4Buffer, err = matchICMP4(message, opts)
				//case *syscall.SockaddrInet6:
				//	match, err = matchICMP6(message, opts)
			}
			if err != nil || l4Protocol == -1 {
				continue
			}

			var l4header L4Header
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
}
