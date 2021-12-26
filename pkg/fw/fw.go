package fw

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/advancevillage/fw/pkg/bpf"
	"github.com/advancevillage/fw/pkg/meta"
	"github.com/advancevillage/fw/pkg/rule"
	"github.com/advancevillage/fw/proto"
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
	Read(ctx context.Context, table *proto.BpfTable) error
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
}

func NewFwMgr(bml int) (IFwMgr, error) {
	protoTable, err := bpf.NewTableClient(protoTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	srcIpTable, err := bpf.NewTableClient(srcIpTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	srcPortTable, err := bpf.NewTableClient(srcPortTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	dstIpTable, err := bpf.NewTableClient(dstIpTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	dstPortTable, err := bpf.NewTableClient(dstPortTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	actionTable, err := bpf.NewTableClient(actionTableName, "lpm_trie", keySize, bml, maxEntries)
	if err != nil {
		return nil, err
	}
	metaTable, err := meta.NewMetadata()
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
	}
	return mgr, nil
}

func (mgr *fwMgr) Read(ctx context.Context, table *proto.BpfTable) error {
	//1. 解析元数据
	if table.Meta == nil {
		table.Meta = make(map[string]string)
	}
	if table.Protocol == nil {
		table.Protocol = make(map[string]string)
	}
	if table.Action == nil {
		table.Action = make(map[string]string)
	}
	if table.SrcIp == nil {
		table.SrcIp = make(map[string]string)
	}
	if table.DstIp == nil {
		table.DstIp = make(map[string]string)
	}
	if table.SrcPort == nil {
		table.SrcPort = make(map[string]string)
	}
	if table.DstPort == nil {
		table.DstPort = make(map[string]string)
	}
	err := mgr.metaTable.QueryMeta(ctx, table)
	if err != nil {
		return err
	}
	//1.解析协议
	table.Protocol, err = mgr.readU8Table(ctx, mgr.protoTable)
	if err != nil {
		return err
	}
	//2. 解析Action
	table.Action, err = mgr.readU8Table(ctx, mgr.actionTable)
	if err != nil {
		return err
	}
	//3. 解析源IP
	table.SrcIp, err = mgr.readU32Table(ctx, mgr.srcIpTable)
	if err != nil {
		return err
	}
	//4. 解析目的IP
	table.DstIp, err = mgr.readU32Table(ctx, mgr.dstIpTable)
	if err != nil {
		return err
	}
	//5. 解析源端口
	table.SrcPort, err = mgr.readU16Table(ctx, mgr.srcPortTable)
	if err != nil {
		return err
	}
	//6. 解析目的端口
	table.DstPort, err = mgr.readU16Table(ctx, mgr.dstPortTable)
	if err != nil {
		return err
	}
	return nil
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

func (mgr *fwMgr) readU8Table(ctx context.Context, tableCli bpf.ITable) (map[string]string, error) {
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
		)
		mask = kk[0] - 0x08*0x0b
		proto = kk[0x0f]
		r[fmt.Sprintf("0x%x/%d", proto, mask)] = hex.EncodeToString(vv)
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

func (mgr *fwMgr) readU32Table(ctx context.Context, tableCli bpf.ITable) (map[string]string, error) {
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
		)
		mask = kk[0] - 0x08*0x08
		r[fmt.Sprintf("%d.%d.%d.%d/%d", vv[0x0c], vv[0x0d], vv[0x0e], vv[0x0f], mask)] = hex.EncodeToString(vv)
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

func (mgr *fwMgr) readU16Table(ctx context.Context, tableCli bpf.ITable) (map[string]string, error) {
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
		)
		mask = kk[0] - 0x08*0x0a
		port = uint16(vv[0x0e]) << 8
		port |= uint16(vv[0x0f])
		r[fmt.Sprintf("0x%x/%d", port, mask)] = hex.EncodeToString(vv)
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
