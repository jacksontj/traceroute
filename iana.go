// Copied from
package traceroute

// Protocol Numbers, Updated: 2015-10-06
const (
	ProtocolICMP      = 1  // Internet Control Message
	ProtocolIPv4      = 4  // IPv4 encapsulation
	ProtocolTCP       = 6  // Transmission Control
	ProtocolUDP       = 17 // User Datagram
	ProtocolIPv6      = 41 // IPv6 encapsulation
	ProtocolIPv6Route = 43 // Routing Header for IPv6
	ProtocolIPv6Frag  = 44 // Fragment Header for IPv6
	ProtocolIPv6ICMP  = 58 // ICMP for IPv6
	ProtocolIPv6NoNxt = 59 // No Next Header for IPv6
	ProtocolIPv6Opts  = 60 // Destination Options for IPv6
)
