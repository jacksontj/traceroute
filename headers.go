package traceroute

type L4Header interface {
	SrcPort() int
	DstPort() int
}

// TODO: Presumably this is in some other library?
type UDPHeader struct {
	Src  uint16
	Dst  uint16
	Ulen uint16
	Csum uint16
}

func (u *UDPHeader) SrcPort() int {
	return int(u.Src)
}

func (u *UDPHeader) DstPort() int {
	return int(u.Dst)
}
