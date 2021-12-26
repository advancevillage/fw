package rule

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
)

type PortMask struct {
	Port uint16
	Mask uint8
}

type IpMask struct {
	Ip   uint32
	Mask uint8
}

type ProtoMask struct {
	Proto uint8
	Mask  uint8
}

func IpMaskEncode(a *IpMask) string {
	var b = []byte{uint8(a.Ip >> 24), uint8(a.Ip >> 16), uint8(a.Ip >> 8), uint8(a.Ip), a.Mask}
	return base64.StdEncoding.EncodeToString(b)
}

func IpMaskDecode(s string) *IpMask {
	a, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return &IpMask{
		Ip: uint32(a[0])&0x000000ff<<24 |
			uint32(a[1])&0x000000ff<<16 |
			uint32(a[2])&0x000000ff<<8 |
			uint32(a[3])&0x000000ff,
		Mask: a[4],
	}
}

func PortMaskEncode(a *PortMask) string {
	var b = []byte{uint8(a.Port >> 8), uint8(a.Port), a.Mask}
	return base64.StdEncoding.EncodeToString(b)
}

func PortMaskDecode(s string) *PortMask {
	a, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return &PortMask{
		Port: uint16(a[0])&0x00ff<<8 | uint16(a[1])&0x00ff,
		Mask: a[2],
	}
}

func ProtoMaskEncode(a *ProtoMask) string {
	var b = []byte{a.Proto, a.Mask}
	return base64.StdEncoding.EncodeToString(b)
}

func ProtoMaskDecode(s string) *ProtoMask {
	a, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return &ProtoMask{
		Proto: a[0],
		Mask:  a[1],
	}
}

func NewPortMask(min, max int) ([]*PortMask, error) {
	return newPortMask(min, max)
}

func newPortMask(min, max int) ([]*PortMask, error) {
	var r = make([]*PortMask, 0, 8)
	if min < 0x00 || max > 0xffff || min > max {
		return nil, errors.New("invalid min max params")
	}

	for v := min; v <= max; {
		probe := 0x01                      //探测指针
		mask := (0xffff << probe) & 0xffff //有效值保证
		for probe <= 0x0f {                //16bit
			n := v + 0xffff - mask
			if n > max || n&mask != v&mask {
				break
			}
			probe++
			mask = (0xffff << probe) & 0xffff
		}
		probe--
		mask = (0xffff << probe) & 0xffff

		n := uint8(0)
		for (mask<<n)&0xffff > 0 {
			n++
		}
		r = append(r, &PortMask{Port: uint16(v & mask), Mask: n})
		v += 0xffff - mask + 1
	}
	return r, nil
}

func newIpMask(s string) (*IpMask, error) {
	if net.ParseIP(s) != nil {
		s = fmt.Sprintf("%s/%d", s, 32)
	}
	var ip, ipnet, err = net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	var r = new(IpMask)
	var ones, bits = ipnet.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only support ipv4")
	}
	r.Mask = uint8(ones)
	ip = ipnet.IP

	r.Ip = uint32(ip[0]&0x000000ff)<<24 | uint32(ip[1]&0x000000ff)<<16 | uint32(ip[2]&0x000000ff)<<8 | uint32(ip[3]&0x000000ff)
	return r, nil
}

const (
	BitmapLength = 128
)

type IBitmap interface {
	Or(a IBitmap)
	Bytes() []byte
	Set(pos uint16)
	Unset(pos uint16)
}

type bitmap struct {
	bit []byte
	n   uint16
}

func NewBitmap(n uint16) IBitmap {
	return &bitmap{bit: make([]byte, n), n: n}
}

func (b *bitmap) Set(pos uint16) {
	if pos >= b.n*0x8 {
		return
	}
	b.bit[pos/0x8] = b.bit[pos/0x8] | (0x1 << (0x7 - pos%0x8))
}

func (b *bitmap) Unset(pos uint16) {
	if pos >= b.n*0x8 {
		return
	}
	b.bit[pos/0x8] = b.bit[pos/0x8] & ^(0x1 << (0x7 - pos%0x8))
}

func (b *bitmap) Bytes() []byte {
	return b.bit
}

func (b *bitmap) Or(a IBitmap) {
	var bb = a.Bytes()
	var nn = uint16(len(bb))
	for i := uint16(0); i < b.n && i < nn; i++ {
		b.bit[i] |= bb[i]
	}
}
