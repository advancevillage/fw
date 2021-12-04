package fw

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/advancevillage/fw/pkg/bpf"
	"github.com/advancevillage/fw/pkg/meta"
	"github.com/advancevillage/fw/pkg/rule"
	"github.com/advancevillage/fw/proto"
	pb "github.com/golang/protobuf/proto"
)

type IFwMgr interface {
	Clean(ctx context.Context, name string, version int) error
	Write(ctx context.Context, name string, version int, rules []*proto.FwRule) error
}

var (
	prefix        = "%s_v%d"
	named         = prefix + "_%s"
	suffixProto   = "proto"
	suffixSrcIp   = "nw_src"
	suffixDstIp   = "nw_dst"
	suffixSrcPort = "tp_src"
	suffixDstPort = "tp_dst"
	suffixRule    = "rule"
	suffixAction  = "action"
)

type fwMgr struct {
	protoTable   bpf.ITable       //协议映射 lpm 8 x/8
	actionTable  bpf.ITable       //动作映射 lpm 8 x/8
	srcIpTable   bpf.ITable       //源IP映射 lpm
	srcPortTable bpf.ITable       //源端口映射 lpm
	dstIpTable   bpf.ITable       //目的IP映射 lpm
	dstPortTable bpf.ITable       //目的端口映射 lpm
	ruleTable    bpf.ITable       //规则表array
	ruleEngine   rule.IRuleEngine //规则引擎
	metaTable    meta.IMeta       //更新内核程序
	mu           sync.Mutex
	bml          int
}

func NewFwMgr(bml int) (IFwMgr, error) {
	protoTable, err := bpf.NewTableClient(suffixProto, "lpm_trie", 8, bml, bml*8)
	if err != nil {
		return nil, err
	}
	srcIpTable, err := bpf.NewTableClient(suffixSrcIp, "lpm_trie", 8, bml, bml*8)
	if err != nil {
		return nil, err
	}
	srcPortTable, err := bpf.NewTableClient(suffixSrcPort, "lpm_trie", 8, bml, bml*8)
	if err != nil {
		return nil, err
	}
	dstIpTable, err := bpf.NewTableClient(suffixDstIp, "lpm_trie", 8, bml, bml*8)
	if err != nil {
		return nil, err
	}
	dstPortTable, err := bpf.NewTableClient(suffixDstPort, "lpm_trie", 8, bml, bml*8)
	if err != nil {
		return nil, err
	}
	actionTable, err := bpf.NewTableClient(suffixAction, "lpm_trie", 8, bml, bml*8)
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

func (mgr *fwMgr) Write(ctx context.Context, name string, version int, rules []*proto.FwRule) error {
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
	var (
		entries   = len(lbvs.Rules) + 2
		fwproto   = fmt.Sprintf(named, name, version, suffixProto)
		fwaction  = fmt.Sprintf(named, name, version, suffixAction)
		fwsrcip   = fmt.Sprintf(named, name, version, suffixSrcIp)
		fwsrcport = fmt.Sprintf(named, name, version, suffixSrcPort)
		fwdstip   = fmt.Sprintf(named, name, version, suffixDstIp)
		fwdstport = fmt.Sprintf(named, name, version, suffixDstPort)
	)
	//2. 设置防火墙名称
	mgr.protoTable.UpdateTableName(fwproto)
	mgr.actionTable.UpdateTableName(fwaction)
	mgr.srcIpTable.UpdateTableName(fwsrcip)
	mgr.srcPortTable.UpdateTableName(fwsrcport)
	mgr.dstIpTable.UpdateTableName(fwdstip)
	mgr.dstPortTable.UpdateTableName(fwdstport)

	mgr.protoTable.UpdateEntries(entries)
	mgr.actionTable.UpdateEntries(entries)
	mgr.srcIpTable.UpdateEntries(entries)
	mgr.srcPortTable.UpdateEntries(entries)
	mgr.dstIpTable.UpdateEntries(entries)
	mgr.dstPortTable.UpdateEntries(entries)
	//3. 写入map
	err = mgr.writeProtoTable(ctx, lbvs.Protocol)
	if err != nil {
		return err
	}
	err = mgr.writeSrcIpTable(ctx, lbvs.SrcIp)
	if err != nil {
		return err
	}
	err = mgr.writeDstIpTable(ctx, lbvs.DstIp)
	if err != nil {
		return err
	}
	err = mgr.writeSrcPortTable(ctx, lbvs.SrcPort)
	if err != nil {
		return err
	}
	err = mgr.writeDstPortTable(ctx, lbvs.DstPort)
	if err != nil {
		return err
	}
	err = mgr.writeActionTable(ctx, lbvs.Action)
	if err != nil {
		return err
	}
	err = mgr.metaTable.UpdateMetaFwProto(ctx, fwproto)
	if err != nil {
		return err
	}
	err = mgr.metaTable.UpdateMetaFwAction(ctx, fwaction)
	if err != nil {
		return err
	}
	err = mgr.metaTable.UpdateMetaFwSrcIp(ctx, fwsrcip)
	if err != nil {
		return err
	}
	err = mgr.metaTable.UpdateMetaFwSrcPort(ctx, fwsrcport)
	if err != nil {
		return err
	}
	err = mgr.metaTable.UpdateMetaFwDstIp(ctx, fwdstip)
	if err != nil {
		return err
	}
	err = mgr.metaTable.UpdateMetaFwDstPort(ctx, fwdstport)
	if err != nil {
		return err
	}
	return nil
}

func (mgr *fwMgr) writeProtoTable(ctx context.Context, table map[string]rule.IBitmap) error {
	if mgr.protoTable.ExistTable(ctx) {
		return errors.New("proto table exist")
	}
	var err = mgr.protoTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.ProtoMaskDecode(key)
		if v == nil || k == nil {
			continue
		}
		var vv = v.Bytes()
		err = mgr.protoTable.UpdateTable(ctx, []byte{k.Mask + 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, k.Proto}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeActionTable(ctx context.Context, table map[string]rule.IBitmap) error {
	if mgr.actionTable.ExistTable(ctx) {
		return errors.New("action table exist")
	}
	var err = mgr.actionTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.ActionMaskDecode(key)
		if v == nil || k == nil {
			continue
		}
		var vv = v.Bytes()
		err = mgr.actionTable.UpdateTable(ctx, []byte{k.Mask + 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, k.Action}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeSrcIpTable(ctx context.Context, table map[string]rule.IBitmap) error {
	if mgr.srcIpTable.ExistTable(ctx) {
		return errors.New("srcIp table exist")
	}
	var err = mgr.srcIpTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.IpMaskDecode(key)
		if k == nil || v == nil {
			continue
		}
		var vv = v.Bytes()
		err = mgr.srcIpTable.UpdateTable(ctx, []byte{k.Mask, 0x00, 0x00, 0x00, uint8(k.Ip >> 24), uint8(k.Ip >> 16), uint8(k.Ip >> 8), uint8(k.Ip)}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeSrcPortTable(ctx context.Context, table map[string]rule.IBitmap) error {
	if mgr.srcPortTable.ExistTable(ctx) {
		return errors.New("srcPort table exist")
	}
	var err = mgr.srcPortTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.PortMaskDecode(key)
		if k == nil || v == nil {
			continue
		}
		var vv = v.Bytes()
		err = mgr.srcPortTable.UpdateTable(ctx, []byte{k.Mask + 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, uint8(k.Port >> 8), uint8(k.Port)}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeDstIpTable(ctx context.Context, table map[string]rule.IBitmap) error {
	if mgr.dstIpTable.ExistTable(ctx) {
		return errors.New("dstIp table exist")
	}
	var err = mgr.dstIpTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.IpMaskDecode(key)
		if k == nil || v == nil {
			continue
		}
		var vv = v.Bytes()
		err = mgr.dstIpTable.UpdateTable(ctx, []byte{k.Mask, 0x00, 0x00, 0x00, uint8(k.Ip >> 24), uint8(k.Ip >> 16), uint8(k.Ip >> 8), uint8(k.Ip)}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeDstPortTable(ctx context.Context, table map[string]rule.IBitmap) error {
	if mgr.dstPortTable.ExistTable(ctx) {
		return errors.New("dstPort table exist")
	}
	var err = mgr.dstPortTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for key, v := range table {
		var k = rule.PortMaskDecode(key)
		if k == nil || v == nil {
			continue
		}
		var vv = v.Bytes()
		err = mgr.dstPortTable.UpdateTable(ctx, []byte{k.Mask + 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, uint8(k.Port >> 8), uint8(k.Port)}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeRuleTable(ctx context.Context, table []*proto.BpfFwRule) error {
	if mgr.ruleTable.ExistTable(ctx) {
		return errors.New("rule table exist")
	}
	var err = mgr.ruleTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for k, v := range table {
		var b, err = pb.Marshal(v)
		if err != nil {
			return err
		}
		var m = make([]byte, 48)
		mgr.encode(m, b)
		err = mgr.ruleTable.UpdateTable(ctx, []byte{uint8(k), uint8(k >> 8), uint8(k >> 16), uint8(k >> 24)}, m)
		if err != nil {
			return err
		}
	}
	return nil
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

func (mgr *fwMgr) Clean(ctx context.Context, name string, version int) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	//1. 设置防火墙名称
	var (
		fwproto   = fmt.Sprintf(named, name, version, suffixProto)
		fwaction  = fmt.Sprintf(named, name, version, suffixAction)
		fwsrcip   = fmt.Sprintf(named, name, version, suffixSrcIp)
		fwsrcport = fmt.Sprintf(named, name, version, suffixSrcPort)
		fwdstip   = fmt.Sprintf(named, name, version, suffixDstIp)
		fwdstport = fmt.Sprintf(named, name, version, suffixDstPort)
	)
	//2. 设置防火墙名称
	mgr.protoTable.UpdateTableName(fwproto)
	mgr.actionTable.UpdateTableName(fwaction)
	mgr.srcIpTable.UpdateTableName(fwsrcip)
	mgr.srcPortTable.UpdateTableName(fwsrcport)
	mgr.dstIpTable.UpdateTableName(fwdstip)
	mgr.dstPortTable.UpdateTableName(fwdstport)

	mgr.protoTable.GCTable(ctx)
	mgr.actionTable.GCTable(ctx)
	mgr.srcIpTable.GCTable(ctx)
	mgr.srcPortTable.GCTable(ctx)
	mgr.dstIpTable.GCTable(ctx)
	mgr.dstPortTable.GCTable(ctx)
	return nil
}
