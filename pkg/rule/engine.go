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
	Protocol map[string]IBitmap
	SrcIp    map[string]IBitmap
	SrcPort  map[string]IBitmap
	DstIp    map[string]IBitmap
	DstPort  map[string]IBitmap
	Action   map[string]IBitmap
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

	numberR = map[uint8]string{
		0x06: TCP,
		0x11: UDP,
		0x01: ICMP,
		0x2f: GRE,
	}

	op = map[string]uint8{
		ACCEPT: 0x01,
		DROP:   0x00,
	}

	l3 = map[string]string{ //默认端口掩码
		ICMP: "0",
		GRE:  "0",
		TCP:  "0-65535",
		UDP:  "0-65535",
	}
)

type EngineOption func(*engine)

type engine struct {
	bml uint16
}

func NewRuleEngine(opts ...EngineOption) IRuleEngine {
	var eng = new(engine)
	for _, opt := range opts {
		opt(eng)
	}
	return eng
}

func WithBitmapLength(x uint16) EngineOption {
	return func(a *engine) {
		a.bml = x
	}
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
		v.Protocol = strings.ToLower(v.GetProtocol())
		v.Action = strings.ToLower(v.GetAction())
		if _, ok := number[v.GetProtocol()]; !ok {
			return nil, fmt.Errorf("don't support %s protocol", v.GetProtocol())
		}
		if _, ok := op[v.GetAction()]; !ok {
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

		ports []string
		err   error
		a     int
		b     int
	)
	if len(rule.GetSrcIp()) <= 0 {
		rule.SrcIp = "0.0.0.0/0"
	}
	if len(rule.GetDstIp()) <= 0 {
		rule.DstIp = "0.0.0.0/0"
	}
	if len(rule.GetSrcPort()) <= 0 {
		rule.SrcPort = l3[rule.GetProtocol()]
	}
	if len(rule.GetDstPort()) <= 0 {
		rule.DstPort = l3[rule.GetProtocol()]
	}
	//解析源端口
	ports = strings.Split(rule.GetSrcPort(), "-")
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
		if a <= 1 && b >= 65535 {
			srcPortMin = 0
			srcPortMax = 65535
		} else {
			srcPortMin = a
			srcPortMax = b
		}
	default:
		return nil, fmt.Errorf("don't support %s format", rule.GetSrcPort())
	}
	//解析目的端口
	ports = strings.Split(rule.GetDstPort(), "-")
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
		if a <= 1 && b >= 65535 {
			dstPortMin = 0
			dstPortMax = 65535
		} else {
			dstPortMin = a
			dstPortMax = b
		}
	default:
		return nil, fmt.Errorf("don't support %s format", rule.GetDstPort())
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

	var (
		protocol = map[string]IBitmap{}
		srcIp    = map[string]IBitmap{}
		srcPort  = map[string]IBitmap{}
		dstIp    = map[string]IBitmap{}
		dstPort  = map[string]IBitmap{}
		action   = map[string]IBitmap{}
	)
	//提取表项
	for _, v := range rules {
		var (
			proto     = uint8(v.GetProtocol())
			protoMask = uint8(0x08)
			nwSrc     = uint32(v.GetSrcIp())
			nwSrcMask = uint8(v.GetSrcIpMask())
			tpSrc     = uint16(v.GetSrcPort())
			tpSrcMask = uint8(v.GetSrcPortMask())
			nwDst     = uint32(v.GetDstIp())
			nwDstMask = uint8(v.GetDstIpMask())
			tpDst     = uint16(v.GetDstPort())
			tpDstMask = uint8(v.GetDstPortMask())
			op        = uint8(v.GetAction())
			opMask    = uint8(0x08)
		)
		//table protocol
		e.addProto(protocol, proto, protoMask)
		//table src ip
		e.addIp(srcIp, nwSrc, nwSrcMask)
		//table src port
		e.addPort(srcPort, tpSrc, tpSrcMask)
		//table dst ip
		e.addIp(dstIp, nwDst, nwDstMask)
		//table dst port
		e.addPort(dstPort, tpDst, tpDstMask)
		//action
		e.addProto(action, op, opMask)
	}
	//设置值
	for i, v := range rules {
		//table protocol
		for key, value := range protocol {
			var (
				match = ProtoMaskDecode(key)
				proto = uint8(v.GetProtocol())
				mask  = uint8(0xff << (0x08 - match.Mask))
			)
			if match == nil {
				continue
			}
			if proto&mask == match.Proto {
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table src ip
		for key, value := range srcIp {
			var (
				match     = IpMaskDecode(key)
				nwSrc     = v.GetSrcIp()
				mask      = uint32(0xffffffff << (0x20 - match.Mask))
				nwSrcMask = uint32(0xffffffff << (0x20 - v.GetSrcIpMask()))
			)
			if match == nil {
				continue
			}
			if nwSrc&nwSrcMask&mask == match.Ip { //匹配
				value.Set(uint16(i))
			} else if match.Ip&mask&nwSrcMask == nwSrc { //包含
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table src port
		for key, value := range srcPort {
			var (
				match     = PortMaskDecode(key)
				tpSrc     = uint16(v.GetSrcPort())
				mask      = uint16(0xffff << (0x10 - match.Mask))
				tpSrcMask = uint16(0xffff << (0x10 - v.GetSrcPortMask()))
			)
			if match == nil {
				continue
			}
			if tpSrc&tpSrcMask&mask == match.Port { //匹配
				value.Set(uint16(i))
			} else if match.Port&mask&tpSrcMask == tpSrc { //包含
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table dst ip
		for key, value := range dstIp {
			var (
				match     = IpMaskDecode(key)
				nwDst     = v.GetDstIp()
				mask      = uint32(0xffffffff << (0x20 - match.Mask))
				nwDstMask = uint32(0xffffffff << (0x20 - v.GetDstIpMask()))
			)
			if match == nil {
				continue
			}
			if nwDst&nwDstMask&mask == match.Ip { //匹配
				value.Set(uint16(i))
			} else if match.Ip&mask&nwDstMask == nwDst { //包含
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table dst port
		for key, value := range dstPort {
			var (
				match     = PortMaskDecode(key)
				tpDst     = uint16(v.GetDstPort())
				mask      = uint16(0xffff << (0x10 - match.Mask))
				tpDstMask = uint16(0xffff << (0x10 - v.GetDstPortMask()))
			)
			if match == nil {
				continue
			}
			if tpDst&tpDstMask&mask == match.Port {
				value.Set(uint16(i))
			} else if match.Port&mask&tpDstMask == tpDst {
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
		//table action
		for key, value := range action {
			var (
				match = ProtoMaskDecode(key)
				op    = uint8(v.GetAction())
				mask  = uint8(0xff << (0x08 - match.Mask))
			)
			if match == nil {
				continue
			}
			if op&mask == match.Proto {
				value.Set(uint16(i))
			} else {
				value.Unset(uint16(i))
			}
		}
	}

	lbvs.Protocol = protocol
	lbvs.SrcIp = srcIp
	lbvs.SrcPort = srcPort
	lbvs.DstIp = dstIp
	lbvs.DstPort = dstPort
	lbvs.Rules = rules
	lbvs.Action = action

	return lbvs
}

func (e *engine) addIp(cidr map[string]IBitmap, ip uint32, mask uint8) {
	var ok = false
	for enc := range cidr {
		var v = IpMaskDecode(enc)
		if v == nil {
			continue
		}
		if v.Ip == ip && v.Mask == mask {
			ok = true
			break
		} else {
			continue
		}
	}
	if !ok {
		cidr[IpMaskEncode(&IpMask{Ip: ip, Mask: mask})] = NewBitmap(e.bml)
	}
}

func (e *engine) addPort(cidr map[string]IBitmap, port uint16, mask uint8) {
	var ok = false
	for enc := range cidr {
		var v = PortMaskDecode(enc)
		if v == nil {
			continue
		}
		if v.Port == port && v.Mask == mask {
			ok = true
			break
		} else {
			continue
		}
	}
	if !ok {
		cidr[PortMaskEncode(&PortMask{Port: port, Mask: mask})] = NewBitmap(e.bml)
	}
}

func (e *engine) addProto(cidr map[string]IBitmap, p uint8, mask uint8) {
	var ok = false
	for enc := range cidr {
		var v = ProtoMaskDecode(enc)
		if v == nil {
			continue
		}
		if v.Proto == p && v.Mask == mask {
			ok = true
			break
		} else {
			continue
		}
	}
	if !ok {
		cidr[ProtoMaskEncode(&ProtoMask{Proto: p, Mask: mask})] = NewBitmap(e.bml)
	}
}

func ProtoStr(p uint8, mask uint8) string {
	var u8mask = uint8(0xff)
	var u8len = uint8(0x08)
	var n = p & (u8mask >> (u8len - mask))
	return numberR[n]
}

func PortStr(p uint16, mask uint8) string {
	var u16mask = uint16(0xffff)
	var u16len = uint8(0x10)
	var n = p & (u16mask >> (u16len - mask))
	var m = n + (0x01 << (u16len - mask)) - 1
	return fmt.Sprintf("%d-%d", n, m)
}

func IpStr(p uint32, mask uint8) string {
	a := uint8(p >> 24)
	b := uint8(p >> 16)
	c := uint8(p >> 8)
	d := uint8(p)
	return fmt.Sprintf("%d.%d.%d.%d/%d", a, b, c, d, mask)
}
