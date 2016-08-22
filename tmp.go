package traceroute

// TODO: pull from some library?
// taken from http://lxr.free-electrons.com/source/include/linux/errqueue.h?v=2.6.32#L6
type SockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
	Info   uint32
	Data   uint32
}
