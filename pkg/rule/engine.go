package rule

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/advancevillage/fw/proto"
)

type IRuleEngine interface {
	Run(rules []*proto.FwRule) (*LBVS, error)
}

type LBVS struct {
	Protocol map[uint8]*Bitmap
	SrcIp    map[*IpMask]*Bitmap
	SrcPort  map[*PortMask]*Bitmap
	DstIp    map[*IpMask]*Bitmap
	DstPort  map[*PortMask]*Bitmap
	Rules    []*proto.BpfFwRule
}

const (
	TCP  = "tcp"
	UDP  = "udp"
	ICMP = "icmp"
	GRE  = "gre"

	ACCEPT = "accept"
	DROP   = "drop"
)

var (
	//doc: https://en.wikipedia.org/wiki/IPv4
	number = map[string]uint8{
		TCP:  0x06,
		UDP:  0x11,
		ICMP: 0x01,
		GRE:  0x2f,
	}

	op = map[string]uint8{
		ACCEPT: 0x00,
		DROP:   0x01,
	}
)

type engine struct{}

func NewRuleEngine() IRuleEngine {
	return &engine{}
}

func (e *engine) Run(rules []*proto.FwRule) (*LBVS, error) {
	var rr, err = e.parse(rules)
	if err != nil {
		return nil, err
	}
	return e.analyze(rr), nil
}

func (e *engine) parse(rules []*proto.FwRule) ([]*proto.BpfFwRule, error) {
	//1. 参数检查
	var rr = make([]*proto.BpfFwRule, 0, len(rules))
	if len(rules) <= 0 {
		return rr, nil
	}

	for _, v := range rules {
		if _, ok := number[strings.ToLower(v.GetProtocol())]; !ok {
			return nil, fmt.Errorf("don't support %s protocol", v.GetProtocol())
		}
		if _, ok := op[strings.ToLower(v.GetAction())]; !ok {
			return nil, fmt.Errorf("don't support %s action", v.GetAction())
		}
		var r, err = e.generate(v)
		if err != nil {
			return nil, err
		}
		rr = append(rr, r...)
	}

	return rr, nil
}

func (e *engine) generate(rule *proto.FwRule) ([]*proto.BpfFwRule, error) {
	var r = make([]*proto.BpfFwRule, 0, 2)
	if rule == nil {
		return r, nil
	}
	var (
		srcPortMin int
		srcPortMax int
		dstPortMin int
		dstPortMax int

		err error
		a   int
		b   int
	)
	if len(rule.GetSrcIp()) <= 0 {
		rule.SrcIp = "0.0.0.0/0"
	}
	if len(rule.GetDstIp()) <= 0 {
		rule.DstIp = "0.0.0.0/0"
	}
	if len(rule.GetSrcPort()) <= 0 {
		rule.SrcPort = "0"
		srcPortMin = 0
		srcPortMax = 0
	} else {
		var ports = strings.Split(rule.GetSrcPort(), "-")
		switch {
		case len(ports) == 1:
			a, err = strconv.Atoi(ports[0])
			if err != nil {
				return nil, err
			}
			srcPortMin = a
			srcPortMax = a
		case len(ports) == 2:
			a, err = strconv.Atoi(ports[0])
			if err != nil {
				return nil, err
			}
			b, err = strconv.Atoi(ports[1])
			if err != nil {
				return nil, err
			}
			if a > b {
				return nil, fmt.Errorf("don't support %s format", rule.GetSrcPort())
			}
			if a == 1 && b == 65535 {
				srcPortMin = 0
				srcPortMax = 0
			} else {
				srcPortMin = a
				srcPortMax = b
			}
		default:
			return nil, fmt.Errorf("don't support %s format", rule.GetSrcPort())
		}
	}
	if len(rule.GetDstPort()) <= 0 {
		rule.DstPort = "0"
		dstPortMin = 0
		dstPortMax = 0
	} else {
		var ports = strings.Split(rule.GetDstPort(), "-")
		switch {
		case len(ports) == 1:
			a, err = strconv.Atoi(ports[0])
			if err != nil {
				return nil, err
			}
			dstPortMin = a
			dstPortMax = a
		case len(ports) == 2:
			a, err = strconv.Atoi(ports[0])
			if err != nil {
				return nil, err
			}
			b, err = strconv.Atoi(ports[1])
			if err != nil {
				return nil, err
			}
			if a > b {
				return nil, fmt.Errorf("don't support %s format", rule.GetDstPort())
			}
			if a == 1 && b == 65535 {
				dstPortMin = 0
				dstPortMax = 0
			} else {
				dstPortMin = a
				dstPortMax = b
			}
		default:
			return nil, fmt.Errorf("don't support %s format", rule.GetDstPort())
		}
	}

	var (
		srcIp   *IpMask
		dstIp   *IpMask
		srcPort []*PortMask
		dstPort []*PortMask
	)

	srcIp, err = newIpMask(rule.GetSrcIp())
	if err != nil {
		return nil, err
	}
	dstIp, err = newIpMask(rule.GetDstIp())
	if err != nil {
		return nil, err
	}
	srcPort, err = newPortMask(srcPortMin, srcPortMax)
	if err != nil {
		return nil, err
	}
	dstPort, err = newPortMask(dstPortMin, dstPortMax)
	if err != nil {
		return nil, err
	}

	for i := range srcPort {
		for j := range dstPort {
			r = append(r, &proto.BpfFwRule{
				Protocol:    uint32(number[strings.ToLower(rule.GetProtocol())] & 0x000000ff),
				SrcIp:       srcIp.Ip,
				SrcIpMask:   uint32(srcIp.Mask & 0x000000ff),
				SrcPort:     uint32(srcPort[i].Port & 0x0000ffff),
				SrcPortMask: uint32(srcPort[i].Mask & 0x000000ff),
				DstIp:       dstIp.Ip,
				DstIpMask:   uint32(dstIp.Mask & 0x000000ff),
				DstPort:     uint32(dstPort[j].Port & 0x0000ffff),
				DstPortMask: uint32(dstPort[j].Mask & 0x000000ff),
				Action:      uint32(op[strings.ToLower(rule.GetAction())] & 0x000000ff),
			})
		}
	}

	return r, nil
}

func (e *engine) analyze(rules []*proto.BpfFwRule) *LBVS {
	var lbvs = &LBVS{}

	var protocol = map[uint8]*Bitmap{
		0x00: newEmptyBitmap(),
	}
	var srcIp = map[*IpMask]*Bitmap{
		&IpMask{Ip: 0x00000000, Mask: 0x00}: newFullBitmap(),
	}
	var srcPort = map[*PortMask]*Bitmap{
		&PortMask{Port: 0x0000, Mask: 0x00}: newFullBitmap(),
	}
	var dstIp = map[*IpMask]*Bitmap{
		&IpMask{Ip: 0x00000000, Mask: 0x00}: newFullBitmap(),
	}
	var dstPort = map[*PortMask]*Bitmap{
		&PortMask{Port: 0x0000, Mask: 0x00}: newFullBitmap(),
	}

	lbvs.Protocol = protocol
	lbvs.SrcIp = srcIp
	lbvs.SrcPort = srcPort
	lbvs.DstIp = dstIp
	lbvs.DstPort = dstPort
	lbvs.Rules = rules

	for i, v := range rules {
		//table protocol
		if vv, ok := protocol[uint8(v.GetProtocol())]; ok {
			vv.Set(uint16(i))
		} else {
			var p = newEmptyBitmap()
			p.Set(uint16(i))
			protocol[uint8(v.GetProtocol())] = p
		}
		//table src ip
		e.addIp(srcIp, v.GetSrcIp(), uint8(v.GetSrcIpMask()))
		for key, value := range srcIp {
			if v.GetSrcIp()&(0xffffffff<<(32-key.Mask)) == key.Ip {
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table src prot
		e.addPort(srcPort, uint16(v.GetSrcPort()), uint8(v.GetSrcPortMask()))
		for key, value := range srcPort {
			if uint16(v.GetSrcPort())&(0xffff<<(16-key.Mask))&0xffff == key.Port {
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table dst ip
		e.addIp(dstIp, v.GetDstIp(), uint8(v.GetDstIpMask()))
		for key, value := range srcIp {
			if v.GetDstIp()&(0xffffffff<<(32-key.Mask)) == key.Ip {
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table dst prot
		e.addPort(dstPort, uint16(v.GetDstPort()), uint8(v.GetDstPortMask()))
		for key, value := range srcPort {
			if uint16(v.GetDstPort())&(0xffff<<(16-key.Mask))&0xffff == key.Port {
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
	}

	return lbvs
}

func (e *engine) addIp(cidr map[*IpMask]*Bitmap, ip uint32, mask uint8) {
	var ok = false
	for k := range cidr {
		if k.Ip == ip && k.Mask == mask {
			ok = true
			break
		} else {
			continue
		}
	}
	if !ok {
		cidr[&IpMask{Ip: ip, Mask: mask}] = newEmptyBitmap()
	}
}

func (e *engine) addPort(cidr map[*PortMask]*Bitmap, port uint16, mask uint8) {
	var ok = false
	for k := range cidr {
		if k.Port == port && k.Mask == mask {
			ok = true
			break
		} else {
			continue
		}
	}
	if !ok {
		cidr[&PortMask{Port: port, Mask: mask}] = newEmptyBitmap()
	}
}