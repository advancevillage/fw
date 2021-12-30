package fw

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/fw/pkg/bpf"
	"github.com/advancevillage/fw/pkg/meta"
	"github.com/advancevillage/fw/pkg/rule"
	"github.com/advancevillage/fw/proto"
	enc "github.com/golang/protobuf/proto"
)

//匹配规则: 16Byte
//  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
// |_____________________________________________________________________________________|
//			     mask
//  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
// |_____________________________________________________________________________________|
//  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
// |_____________________________________________________________________________________|
//				 zone
//  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
// |_____________________________________________________________________________________|
//				 key

type IFwMgr interface {
	Read(ctx context.Context) ([]*proto.FwRule, error)
	Write(ctx context.Context, version int, rules []*proto.FwRule) error
}

var (
	suffixProto   = "proto"
	suffixSrcIp   = "nw_src"
	suffixDstIp   = "nw_dst"
	suffixSrcPort = "tp_src"
	suffixDstPort = "tp_dst"
	suffixAction  = "action"

	protoTableName   = fmt.Sprintf("%s_%s", "ipv4", suffixProto)
	srcIpTableName   = fmt.Sprintf("%s_%s", "ipv4", suffixSrcIp)
	srcPortTableName = fmt.Sprintf("%s_%s", "ipv4", suffixSrcPort)
	dstIpTableName   = fmt.Sprintf("%s_%s", "ipv4", suffixDstIp)
	dstPortTableName = fmt.Sprintf("%s_%s", "ipv4", suffixDstPort)
	actionTableName  = fmt.Sprintf("%s_%s", "ipv4", suffixAction)

	keySize    = 0x10
	maxEntries = 0x01 << 16
)

type fwMgr struct {
	protoTable   bpf.ITable       //协议映射 lpm 8 x/8
	actionTable  bpf.ITable       //动作映射 lpm 8 x/8
	srcIpTable   bpf.ITable       //源IP映射 lpm
	srcPortTable bpf.ITable       //源端口映射 lpm
	dstIpTable   bpf.ITable       //目的IP映射 lpm
	dstPortTable bpf.ITable       //目的端口映射 lpm
	ruleEngine   rule.IRuleEngine //规则引擎
	metaTable    meta.IMeta       //更新内核程序
	mu           sync.Mutex
	bml          int
	logger       logx.ILogger
}

func NewFwMgr(logger logx.ILogger, bml int) (IFwMgr, error) {
	protoTable, err := bpf.NewTableClient(logger, protoTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	srcIpTable, err := bpf.NewTableClient(logger, srcIpTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	srcPortTable, err := bpf.NewTableClient(logger, srcPortTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	dstIpTable, err := bpf.NewTableClient(logger, dstIpTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	dstPortTable, err := bpf.NewTableClient(logger, dstPortTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	actionTable, err := bpf.NewTableClient(logger, actionTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	metaTable, err := meta.NewMetadata(logger)
	if err != nil {
		return nil, err
	}

	ruleEngine := rule.NewRuleEngine(rule.WithBitmapLength(uint16(bml)))

	var mgr = &fwMgr{
		protoTable:   protoTable,
		actionTable:  actionTable,
		srcIpTable:   srcIpTable,
		srcPortTable: srcPortTable,
		dstIpTable:   dstIpTable,
		dstPortTable: dstPortTable,
		ruleEngine:   ruleEngine,
		metaTable:    metaTable,
		bml:          bml,
		logger:       logger,
	}
	return mgr, nil
}

func (mgr *fwMgr) Read(ctx context.Context) ([]*proto.FwRule, error) {
	//1. 解析元数据
	var table = &proto.BpfTable{
		Meta:     make(map[string]string),
		Protocol: make(map[string]string),
		Action:   make(map[string]string),
		SrcIp:    make(map[string]string),
		DstIp:    make(map[string]string),
		SrcPort:  make(map[string]string),
		DstPort:  make(map[string]string),
	}
	err := mgr.metaTable.QueryMeta(ctx, table)
	if err != nil {
		return nil, err
	}
	var zone = mgr.parseZone(table.Meta)
	//1.解析协议
	table.Protocol, err = mgr.readU8Table(ctx, mgr.protoTable, zone)
	if err != nil {
		return nil, err
	}
	//2. 解析Action
	table.Action, err = mgr.readU8Table(ctx, mgr.actionTable, zone)
	if err != nil {
		return nil, err
	}
	//3. 解析源IP
	table.SrcIp, err = mgr.readU32Table(ctx, mgr.srcIpTable, zone)
	if err != nil {
		return nil, err
	}
	//4. 解析目的IP
	table.DstIp, err = mgr.readU32Table(ctx, mgr.dstIpTable, zone)
	if err != nil {
		return nil, err
	}
	//5. 解析源端口
	table.SrcPort, err = mgr.readU16Table(ctx, mgr.srcPortTable, zone)
	if err != nil {
		return nil, err
	}
	//6. 解析目的端口
	table.DstPort, err = mgr.readU16Table(ctx, mgr.dstPortTable, zone)
	if err != nil {
		return nil, err
	}
	return mgr.analyze(ctx, table)
}

func (mgr *fwMgr) Write(ctx context.Context, version int, rules []*proto.FwRule) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	//1. 解析防火墙规则
	var lbvs, err = mgr.ruleEngine.Run(rules)
	if err != nil {
		return err
	}
	if lbvs == nil || lbvs.Protocol == nil || lbvs.SrcIp == nil || lbvs.SrcPort == nil || lbvs.DstIp == nil || lbvs.DstPort == nil || lbvs.Rules == nil {
		return errors.New("parse firewall rule fail")
	}
	//3. 写入map
	err = mgr.writeU8Table(ctx, mgr.protoTable, lbvs.Protocol, version)
	if err != nil {
		return err
	}
	err = mgr.writeU32Table(ctx, mgr.srcIpTable, lbvs.SrcIp, version)
	if err != nil {
		return err
	}
	err = mgr.writeU32Table(ctx, mgr.dstIpTable, lbvs.DstIp, version)
	if err != nil {
		return err
	}
	err = mgr.writeU16Table(ctx, mgr.srcPortTable, lbvs.SrcPort, version)
	if err != nil {
		return err
	}
	err = mgr.writeU16Table(ctx, mgr.dstPortTable, lbvs.DstPort, version)
	if err != nil {
		return err
	}
	err = mgr.writeU8Table(ctx, mgr.actionTable, lbvs.Action, version)
	if err != nil {
		return err
	}
	err = mgr.metaTable.UpdateZone(ctx, version)
	if err != nil {
		return err
	}
	return nil
}

func (mgr *fwMgr) writeU8Table(ctx context.Context, tableCli bpf.ITable, table map[string]rule.IBitmap, zone int) error {
	var err error
	if tableCli == nil {
		return nil
	}
	if !tableCli.ExistTable(ctx) {
		err = tableCli.CreateTable(ctx)
	}
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.ProtoMaskDecode(key)
		if v == nil || k == nil {
			continue
		}
		var kk = make([]byte, keySize)
		kk[0x00] = k.Mask + 0x08*0x0b
		kk[0x01] = 0x00
		kk[0x02] = 0x00
		kk[0x03] = 0x00
		kk[0x04] = uint8(zone >> 24)
		kk[0x05] = uint8(zone >> 16)
		kk[0x06] = uint8(zone >> 8)
		kk[0x07] = uint8(zone)
		kk[0x08] = 0x00
		kk[0x09] = 0x00
		kk[0x0a] = 0x00
		kk[0x0b] = 0x00
		kk[0x0c] = 0x00
		kk[0x0d] = 0x00
		kk[0x0e] = 0x00
		kk[0x0f] = k.Proto
		var vv = v.Bytes()
		err = tableCli.UpdateTable(ctx, kk, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) readU8Table(ctx context.Context, tableCli bpf.ITable, zone int) (map[string]string, error) {
	var r = make(map[string]string)
	if tableCli == nil {
		return r, nil
	}
	if !tableCli.ExistTable(ctx) {
		return r, nil
	}
	var kv, err = tableCli.QueryTable(ctx)
	if err != nil {
		return r, err
	}
	for i := range kv {
		var (
			kk    = kv[i].Key
			vv    = kv[i].Value
			mask  uint8
			proto uint8
			ver   int
		)
		ver = int(kk[0x04]) << 24
		ver |= int(kk[0x05]) << 16
		ver |= int(kk[0x06]) << 8
		ver |= int(kk[0x07])

		if ver != zone {
			tableCli.DeleteTable(ctx, kk)
			continue
		}

		mask = kk[0] - 0x08*0x0b
		proto = kk[0x0f]
		r[rule.ProtoMaskEncode(&rule.ProtoMask{Proto: proto, Mask: mask})] = hex.EncodeToString(vv)
	}
	return r, nil
}

func (mgr *fwMgr) writeU32Table(ctx context.Context, tableCli bpf.ITable, table map[string]rule.IBitmap, zone int) error {
	var err error
	if tableCli == nil {
		return nil
	}
	if !tableCli.ExistTable(ctx) {
		err = tableCli.CreateTable(ctx)
	}
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.IpMaskDecode(key)
		if k == nil || v == nil {
			continue
		}
		var kk = make([]byte, keySize)
		kk[0x00] = k.Mask + 0x08*0x08
		kk[0x01] = 0x00
		kk[0x02] = 0x00
		kk[0x03] = 0x00
		kk[0x04] = uint8(zone >> 24)
		kk[0x05] = uint8(zone >> 16)
		kk[0x06] = uint8(zone >> 8)
		kk[0x07] = uint8(zone)
		kk[0x08] = 0x00
		kk[0x09] = 0x00
		kk[0x0a] = 0x00
		kk[0x0b] = 0x00
		kk[0x0c] = uint8(k.Ip >> 24)
		kk[0x0d] = uint8(k.Ip >> 16)
		kk[0x0e] = uint8(k.Ip >> 8)
		kk[0x0f] = uint8(k.Ip)
		var vv = v.Bytes()
		err = tableCli.UpdateTable(ctx, kk, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) readU32Table(ctx context.Context, tableCli bpf.ITable, zone int) (map[string]string, error) {
	var r = make(map[string]string)
	if tableCli == nil {
		return r, nil
	}
	if !tableCli.ExistTable(ctx) {
		return r, nil
	}
	var kv, err = tableCli.QueryTable(ctx)
	if err != nil {
		return r, err
	}
	for i := range kv {
		var (
			kk   = kv[i].Key
			vv   = kv[i].Value
			mask uint8
			ver  int
			ip   uint32
		)
		ver = int(kk[0x04]) << 24
		ver |= int(kk[0x05]) << 16
		ver |= int(kk[0x06]) << 8
		ver |= int(kk[0x07])
		if ver != zone {
			tableCli.DeleteTable(ctx, kk)
			continue
		}
		mask = kk[0] - 0x08*0x08
		ip = uint32(kk[0x0c]) << 24
		ip |= uint32(kk[0x0d]) << 16
		ip |= uint32(kk[0x0e]) << 8
		ip |= uint32(kk[0x0f])
		r[rule.IpMaskEncode(&rule.IpMask{Ip: ip, Mask: mask})] = hex.EncodeToString(vv)
	}
	return r, nil
}

func (mgr *fwMgr) writeU16Table(ctx context.Context, tableCli bpf.ITable, table map[string]rule.IBitmap, zone int) error {
	var err error
	if tableCli == nil {
		return nil
	}
	if !tableCli.ExistTable(ctx) {
		err = tableCli.CreateTable(ctx)
	}
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.PortMaskDecode(key)
		if k == nil || v == nil {
			continue
		}
		var kk = make([]byte, keySize)
		kk[0x00] = k.Mask + 0x08*0x0a
		kk[0x01] = 0x00
		kk[0x02] = 0x00
		kk[0x03] = 0x00
		kk[0x04] = uint8(zone >> 24)
		kk[0x05] = uint8(zone >> 16)
		kk[0x06] = uint8(zone >> 8)
		kk[0x07] = uint8(zone)
		kk[0x08] = 0x00
		kk[0x09] = 0x00
		kk[0x0a] = 0x00
		kk[0x0b] = 0x00
		kk[0x0c] = 0x00
		kk[0x0d] = 0x00
		kk[0x0e] = uint8(k.Port >> 8)
		kk[0x0f] = uint8(k.Port)
		var vv = v.Bytes()
		err = tableCli.UpdateTable(ctx, kk, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) readU16Table(ctx context.Context, tableCli bpf.ITable, zone int) (map[string]string, error) {
	var r = make(map[string]string)
	if tableCli == nil {
		return r, nil
	}
	if !tableCli.ExistTable(ctx) {
		return r, nil
	}
	var kv, err = tableCli.QueryTable(ctx)
	if err != nil {
		return r, err
	}
	for i := range kv {
		var (
			kk   = kv[i].Key
			vv   = kv[i].Value
			mask uint8
			port uint16
			ver  int
		)
		ver = int(kk[0x04]) << 24
		ver |= int(kk[0x05]) << 16
		ver |= int(kk[0x06]) << 8
		ver |= int(kk[0x07])
		if ver != zone {
			tableCli.DeleteTable(ctx, kk)
			continue
		}

		mask = kk[0] - 0x08*0x0a
		port = uint16(kk[0x0e]) << 8
		port |= uint16(kk[0x0f])
		r[rule.PortMaskEncode(&rule.PortMask{Port: port, Mask: mask})] = hex.EncodeToString(vv)
	}
	return r, nil
}

func (mgr *fwMgr) encode(m []byte, s []byte) {
	//protocol: 4Byte
	//  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
	// |_______|_______|____________________|
	//    ver     ihl		   tos
	//  0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
	// |____________________________________|
	//		     total length
	// big endian
	m[0] = 0x10 | 0x04
	m[1] = 0x00
	m[2] = 0xff & uint8((len(s) + 4))
	m[3] = 0xff & uint8((len(s)+4)>>8)
	copy(m[4:], s)
}

func (mgr *fwMgr) parseZone(meta map[string]string) int {
	var zone = 0
	if meta == nil {
		return zone
	}
	s, ok := meta["fw.zone"]
	if !ok {
		return zone
	}
	zone, err := strconv.Atoi(s)
	if err != nil {
		return zone
	}
	return zone
}

func (mgr *fwMgr) analyze(ctx context.Context, table *proto.BpfTable) ([]*proto.FwRule, error) {
	var rules []*proto.FwRule
	var (
		u8mask  = uint8(0xff)
		u8len   = uint8(0x08)
		u16mask = uint16(0xffff)
		u16len  = uint8(0x10)
		u32mask = uint32(0xffffffff)
		u32len  = uint8(0x20)
	)

	//bitmap 从低位向高位递进
	for i := 0; i < mgr.bml*8; i++ {
		//解析协议
		var (
			protocol = &rule.ProtoMask{Proto: 0xff, Mask: 0xff}
			srcIp    = &rule.IpMask{Ip: 0xffffffff, Mask: 0xff}
			dstIp    = &rule.IpMask{Ip: 0xffffffff, Mask: 0xff}
			srcPort  = &rule.PortMask{Port: 0xffff, Mask: 0xff}
			dstPort  = &rule.PortMask{Port: 0xffff, Mask: 0xff}
			action   = &rule.ProtoMask{Proto: 0xff, Mask: 0xff}
		)

		var (
			cur   = i / 8
			pos   = i % 8
			probe = uint8(0x80)
		)
		for k, v := range table.Protocol {
			//bitmap
			b, err := hex.DecodeString(v)
			if err != nil {
				return nil, err
			}
			o := rule.ProtoMaskDecode(k)
			if nil == o {
				return nil, errors.New("proto encode err")
			}

			if b[cur]&(probe>>pos) == 0x0 {
				continue
			}

			if mgr.isEmptyU8(protocol) {
				protocol.Proto = o.Proto
				protocol.Mask = o.Mask
				continue
			}

			if protocol.Proto&(u8mask<<(u8len-o.Mask)) == o.Proto {
				protocol.Proto = o.Proto
				protocol.Mask = o.Mask
				continue
			}
		}

		for k, v := range table.Action {
			//bitmap
			b, err := hex.DecodeString(v)
			if err != nil {
				return nil, err
			}
			o := rule.ProtoMaskDecode(k)
			if nil == o {
				return nil, errors.New("action encode err")
			}

			if b[cur]&(probe>>pos) == 0x0 {
				continue
			}

			if mgr.isEmptyU8(action) {
				action.Proto = o.Proto
				action.Mask = o.Mask
				continue
			}

			if action.Proto&(u8mask<<(u8len-o.Mask)) == o.Proto {
				action.Proto = o.Proto
				action.Mask = o.Mask
				continue
			}
		}

		for k, v := range table.SrcIp {
			//bitmap
			b, err := hex.DecodeString(v)
			if err != nil {
				return nil, err
			}
			o := rule.IpMaskDecode(k)
			if nil == o {
				return nil, errors.New("ip encode err")
			}

			if b[cur]&(probe>>pos) == 0x0 {
				continue
			}

			if mgr.isEmptyU32(srcIp) {
				srcIp.Ip = o.Ip
				srcIp.Mask = o.Mask
				continue
			}

			if srcIp.Ip&(u32mask<<(u32len-o.Mask)) == o.Ip {
				srcIp.Ip = o.Ip
				srcIp.Mask = o.Mask
				continue
			}
		}

		for k, v := range table.SrcPort {
			//bitmap
			b, err := hex.DecodeString(v)
			if err != nil {
				return nil, err
			}
			o := rule.PortMaskDecode(k)
			if nil == o {
				return nil, errors.New("port encode err")
			}

			if b[cur]&(probe>>pos) == 0x0 {
				continue
			}

			if mgr.isEmptyU16(srcPort) {
				srcPort.Port = o.Port
				srcPort.Mask = o.Mask
				continue
			}

			if srcPort.Port&(u16mask<<(u16len-o.Mask)) == o.Port {
				srcPort.Port = o.Port
				srcPort.Mask = o.Mask
				continue
			}
		}

		for k, v := range table.DstIp {
			//bitmap
			b, err := hex.DecodeString(v)
			if err != nil {
				return nil, err
			}
			o := rule.IpMaskDecode(k)
			if nil == o {
				return nil, errors.New("ip encode err")
			}

			if b[cur]&(probe>>pos) == 0x0 {
				continue
			}

			if mgr.isEmptyU32(dstIp) {
				dstIp.Ip = o.Ip
				dstIp.Mask = o.Mask
				continue
			}

			if dstIp.Ip&(u32mask<<(u32len-o.Mask)) == o.Ip {
				dstIp.Ip = o.Ip
				dstIp.Mask = o.Mask
				continue
			}
		}

		for k, v := range table.DstPort {
			//bitmap
			b, err := hex.DecodeString(v)
			if err != nil {
				return nil, err
			}
			o := rule.PortMaskDecode(k)
			if nil == o {
				return nil, errors.New("port encode err")
			}

			if b[cur]&(probe>>pos) == 0x0 {
				continue
			}

			if mgr.isEmptyU16(dstPort) {
				dstPort.Port = o.Port
				dstPort.Mask = o.Mask
				continue
			}

			if dstPort.Port&(u16mask<<(u16len-o.Mask)) == o.Port {
				dstPort.Port = o.Port
				dstPort.Mask = o.Mask
				continue
			}
		}

		if mgr.isEmptyU8(protocol) && mgr.isEmptyU16(srcPort) && mgr.isEmptyU32(srcIp) && mgr.isEmptyU32(dstIp) && mgr.isEmptyU16(dstPort) && mgr.isEmptyU8(action) {
			break
		}

		var rule = &proto.FwRule{
			Protocol: rule.ProtoStr(protocol.Proto, protocol.Mask),
			SrcPort:  rule.PortStr(srcPort.Port, srcPort.Mask),
			SrcIp:    rule.IpStr(srcIp.Ip, srcIp.Mask),
			DstIp:    rule.IpStr(dstIp.Ip, dstIp.Mask),
			DstPort:  rule.PortStr(dstPort.Port, dstPort.Mask),
			Action:   rule.ActionStr(action.Proto, action.Mask),
		}

		rules = append(rules, rule)
	}

	//端口区间合并
	return mgr.portMerge(ctx, rules), nil
}

func (mgr *fwMgr) isEmptyU8(a *rule.ProtoMask) bool {
	return a.Proto == 0xff && a.Mask == 0xff
}

func (mgr *fwMgr) isEmptyU16(a *rule.PortMask) bool {
	return a.Port == 0xffff && a.Mask == 0xff
}

func (mgr *fwMgr) isEmptyU32(a *rule.IpMask) bool {
	return a.Ip == 0xffffffff && a.Mask == 0xff
}

func (mgr *fwMgr) portMerge(ctx context.Context, rules []*proto.FwRule) []*proto.FwRule {
	//端口区间合并
	var srcPort = make(map[string][]string) //base64: ["22-23","23-31","32-63"...]
	var rule = &proto.FwRule{}
	for _, v := range rules {
		rule.Protocol = v.GetProtocol()
		rule.SrcIp = v.GetSrcIp()
		rule.DstIp = v.GetDstIp()
		rule.DstPort = v.GetDstPort()
		rule.Action = v.GetAction()

		var k = mgr.ruleEncode(rule)
		if _, ok := srcPort[k]; ok {
			srcPort[k] = append(srcPort[k], v.GetSrcPort())
		} else {
			srcPort[k] = []string{v.GetSrcPort()}
		}
	}

	rules = rules[:0]
	for k, v := range srcPort {
		var item = mgr.ruleDecode(k)
		if item == nil {
			continue
		}
		v = mgr.merge(v)
		for i := range v {
			rules = append(rules, &proto.FwRule{
				Protocol: item.GetProtocol(),
				SrcIp:    item.GetSrcIp(),
				DstIp:    item.GetDstIp(),
				DstPort:  item.GetDstPort(),
				SrcPort:  v[i],
				Action:   item.GetAction(),
			})
		}
	}

	var dstPort = make(map[string][]string) //base64: ["22-23","23-31","32-63"...]
	for _, v := range rules {
		rule.Protocol = v.GetProtocol()
		rule.SrcIp = v.GetSrcIp()
		rule.DstIp = v.GetDstIp()
		rule.SrcPort = v.GetSrcPort()
		rule.Action = v.GetAction()

		var k = mgr.ruleEncode(rule)
		if _, ok := dstPort[k]; ok {
			dstPort[k] = append(dstPort[k], v.GetDstPort())
		} else {
			dstPort[k] = []string{v.GetDstPort()}
		}
	}

	rules = rules[:0]
	for k, v := range dstPort {
		var item = mgr.ruleDecode(k)
		if item == nil {
			continue
		}
		v = mgr.merge(v)
		for i := range v {
			rules = append(rules, &proto.FwRule{
				Protocol: item.GetProtocol(),
				SrcIp:    item.GetSrcIp(),
				DstIp:    item.GetDstIp(),
				DstPort:  v[i],
				SrcPort:  item.GetSrcPort(),
				Action:   item.GetAction(),
			})
		}
	}

	return rules
}

func (mgr *fwMgr) merge(interval []string) []string {
	var sample = make([][]int, 0, len(interval))
	for _, v := range interval {
		a, err := strconv.Atoi(strings.Split(v, "-")[0])
		if err != nil {
			return nil
		}
		b, err := strconv.Atoi(strings.Split(v, "-")[1])
		if err != nil {
			return nil
		}
		sample = append(sample, []int{a, b})
	}
	sample = merge(sample)
	interval = interval[:0]
	for _, v := range sample {
		switch {
		case v[0] == 0 && v[1] == 0:
			interval = append(interval, "")
		case v[0] == 0 && v[1] == 65535:
			interval = append(interval, "")
		case v[0] == v[1]:
			interval = append(interval, fmt.Sprintf("%d", v[0]))
		case v[0] < v[1]:
			interval = append(interval, fmt.Sprintf("%d-%d", v[0], v[1]))
		default:
			continue
		}
	}
	return interval
}

func (mgr *fwMgr) ruleEncode(rule *proto.FwRule) string {
	var b, err = enc.Marshal(rule)
	if err != nil {
		return err.Error()
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (mgr *fwMgr) ruleDecode(rule string) *proto.FwRule {
	b, err := base64.StdEncoding.DecodeString(rule)
	if err != nil {
		return nil
	}
	var a = &proto.FwRule{}
	err = enc.Unmarshal(b, a)
	if err != nil {
		return nil
	}
	return a
}

func merge(intervals [][]int) [][]int {
	//对区间左边界升序排序
	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i][0] < intervals[j][0]
	})
	var (
		r    = [][]int{}
		prev = intervals[0] //初始值
	)

	for i := 1; i < len(intervals); i++ {
		var cur = intervals[i]
		if prev[1] < cur[0]-1 { //左边界 > 右边界 [0,21] [22, 100]
			r = append(r, prev)
			prev = cur
			continue
		}
		if prev[1] < cur[1] {
			prev[1] = cur[1]
		}
	}
	r = append(r, prev)
	return r
}
