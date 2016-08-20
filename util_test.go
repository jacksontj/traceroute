package traceroute

import (
	"net"
	"syscall"
	"testing"
)

func TestAddrToSockAddr(t *testing.T) {
	origIP := net.ParseIP("173.194.72.99")
	origPort := 34456
	s := ipPortToSockaddr(origIP, origPort)

	var ip net.IP
	switch t := s.(type) {
	case *syscall.SockaddrInet4:
		ip = net.IP(t.Addr[:])
	case *syscall.SockaddrInet6:
		ip = net.IP(t.Addr[:])
	}
	if !ip.Equal(origIP) {
		t.Error("IPs don't match! orig=%v parsed=%v", origIP.String(), ip.String())
	}
}
