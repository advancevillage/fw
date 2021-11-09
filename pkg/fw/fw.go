package fw

import (
	"context"
	"errors"
	"fmt"

	"github.com/advancevillage/fw/pkg/bpf"
	"github.com/advancevillage/fw/pkg/rule"
	"github.com/advancevillage/fw/proto"
	pb "github.com/golang/protobuf/proto"
)

type IFwMgr interface {
	Clean(ctx context.Context, name string, version int) error
	Write(ctx context.Context, name string, version int, rules []*proto.FwRule) error
}

type fwMgr struct {
	protoTable   bpf.ITable //协议映射 lpm 8 x/8
	srcIpTable   bpf.ITable //源IP映射 lpm
	srcPortTable bpf.ITable //源端口映射 lpm
	dstIpTable   bpf.ITable //目的IP映射 lpm
	dstPortTable bpf.ITable //目的端口映射 lpm
	ruleTable    bpf.ITable //规则表array

	ruleEngine rule.IRuleEngine
}

func NewFwMgr() (IFwMgr, error) {
	protoTable, err := bpf.NewTableClient("proto", "lpm_trie", 5, rule.BitmapLength, rule.BitmapLength*8)
	if err != nil {
		return nil, err
	}
	srcIpTable, err := bpf.NewTableClient("srcIp", "lpm_trie", 8, rule.BitmapLength, rule.BitmapLength*8)
	if err != nil {
		return nil, err
	}
	srcPortTable, err := bpf.NewTableClient("srcPort", "lpm_trie", 6, rule.BitmapLength, rule.BitmapLength*8)
	if err != nil {
		return nil, err
	}
	dstIpTable, err := bpf.NewTableClient("dstIp", "lpm_trie", 8, rule.BitmapLength, rule.BitmapLength*8)
	if err != nil {
		return nil, err
	}
	dstPortTable, err := bpf.NewTableClient("dstPort", "lpm_trie", 6, rule.BitmapLength, rule.BitmapLength*8)
	if err != nil {
		return nil, err
	}
	ruleTable, err := bpf.NewTableClient("rules", "array", 4, 48, rule.BitmapLength*8)
	if err != nil {
		return nil, err
	}
	ruleEngine := rule.NewRuleEngine()

	var mgr = &fwMgr{
		protoTable:   protoTable,
		srcIpTable:   srcIpTable,
		srcPortTable: srcPortTable,
		dstIpTable:   dstIpTable,
		dstPortTable: dstPortTable,
		ruleTable:    ruleTable,
		ruleEngine:   ruleEngine,
	}
	return mgr, nil
}

func (mgr *fwMgr) Write(ctx context.Context, name string, version int, rules []*proto.FwRule) error {
	//1. 解析防火墙规则
	var lbvs, err = mgr.ruleEngine.Run(rules)
	if err != nil {
		return err
	}
	if lbvs == nil || lbvs.Protocol == nil || lbvs.SrcIp == nil || lbvs.SrcPort == nil || lbvs.DstIp == nil || lbvs.DstPort == nil || lbvs.Rules == nil {
		return errors.New("parse firewall rule fail")
	}
	//2. 设置防火墙名称
	mgr.protoTable.UpdateTableName(fmt.Sprintf("%sV%d%s", name, version, "Proto"))
	mgr.srcIpTable.UpdateTableName(fmt.Sprintf("%sV%d%s", name, version, "SrcIp"))
	mgr.srcPortTable.UpdateTableName(fmt.Sprintf("%sV%d%s", name, version, "SrcPort"))
	mgr.dstIpTable.UpdateTableName(fmt.Sprintf("%sV%d%s", name, version, "DstIp"))
	mgr.dstPortTable.UpdateTableName(fmt.Sprintf("%sV%d%s", name, version, "DstPort"))
	mgr.ruleTable.UpdateTableName(fmt.Sprintf("%sV%d%s", name, version, "Rule"))
	//3. 写入map
	err = mgr.writeRuleTable(ctx, lbvs.Rules)
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
	err = mgr.writeProtoTable(ctx, lbvs.Protocol)
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
	return nil
}

func (mgr *fwMgr) writeProtoTable(ctx context.Context, table map[uint8]rule.IBitmap) error {
	var err = mgr.protoTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for k, v := range table {
		if v == nil {
			continue
		}
		var vv = v.Bytes()
		err = mgr.protoTable.UpdateTable(ctx, []byte{0x08, 0x00, 0x00, 0x00, k}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeSrcIpTable(ctx context.Context, table map[string]rule.IBitmap) error {
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
		err = mgr.srcPortTable.UpdateTable(ctx, []byte{k.Mask, 0x00, 0x00, 0x00, uint8(k.Port >> 8), uint8(k.Port)}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeDstIpTable(ctx context.Context, table map[string]rule.IBitmap) error {
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
		err = mgr.dstPortTable.UpdateTable(ctx, []byte{k.Mask, 0x00, 0x00, 0x00, uint8(k.Port >> 8), uint8(k.Port)}, vv)
		if err != nil {
			return err
		}
	}
	return nil
}

func (mgr *fwMgr) writeRuleTable(ctx context.Context, table []*proto.BpfFwRule) error {
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
	//1. 设置防火墙名称
	mgr.protoTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.srcIpTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.srcPortTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.dstIpTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.dstPortTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.ruleTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))

	mgr.protoTable.GCTable(ctx)
	mgr.srcIpTable.GCTable(ctx)
	mgr.srcPortTable.GCTable(ctx)
	mgr.dstIpTable.GCTable(ctx)
	mgr.dstPortTable.GCTable(ctx)
	mgr.ruleTable.GCTable(ctx)

	return nil
}
