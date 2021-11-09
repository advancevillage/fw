package rule

import (
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

func newPortMask(min, max int) ([]*PortMask, error) {
	var r = make([]*PortMask, 0, 8)
	if min < 0x00 || max > 0xffff || min > max {
		return nil, errors.New("invalid min max params")
	}
	//特殊处理
	//eg: min = 0 max = 0  理论值 0/16
	//处理:
	//eg: min = 0 max = 0  实际值 0/0
	//结果:
	//减少规则数量, 提高效率
	if min == 0 && max == 0 {
		r = append(r, &PortMask{Port: 0x0000, Mask: 0})
		return r, nil
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

type Bitmap [BitmapLength]byte

func (b *Bitmap) Set(pos uint16) {
	if pos >= BitmapLength*0x8 {
		return
	}
	b[pos/0x8] = b[pos/0x8] | (0x1 << (0x7 - pos%0x8))
}

func (b *Bitmap) Unset(pos uint16) {
	if pos >= BitmapLength*0x8 {
		return
	}
	b[pos/0x8] = b[pos/0x8] & ^(0x1 << (0x7 - pos%0x8))
}

func newEmptyBitmap() *Bitmap {
	var b = new(Bitmap)
	for i := uint16(0); i < BitmapLength*8; i++ {
		b.Unset(i)
	}
	return b
}

func newFullBitmap() *Bitmap {
	var b = new(Bitmap)
	for i := uint16(0); i < BitmapLength*8; i++ {
		b.Set(i)
	}
	return b
}
