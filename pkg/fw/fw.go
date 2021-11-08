package fw

import (
	"context"
	"errors"
	"fmt"

	"github.com/advancevillage/fw/pkg/bpf"
	"github.com/advancevillage/fw/pkg/rule"
	"github.com/advancevillage/fw/proto"
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
	protoTable, err := bpf.NewTableClient("proto", "lpm_trie", 5, 256, 2048)
	if err != nil {
		return nil, err
	}
	srcIpTable, err := bpf.NewTableClient("srcIp", "lpm_trie", 8, 256, 2048)
	if err != nil {
		return nil, err
	}
	srcPortTable, err := bpf.NewTableClient("srcPort", "lpm_trie", 6, 256, 2048)
	if err != nil {
		return nil, err
	}
	dstIpTable, err := bpf.NewTableClient("dstIp", "lpm_trie", 8, 256, 2048)
	if err != nil {
		return nil, err
	}
	dstPortTable, err := bpf.NewTableClient("dstPort", "lpm_trie", 6, 256, 2048)
	if err != nil {
		return nil, err
	}
	ruleTable, err := bpf.NewTableClient("rules", "array", 4, 64, 2048)
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
	mgr.protoTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.srcIpTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.srcPortTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.dstIpTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.dstPortTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	mgr.ruleTable.UpdateTableName(fmt.Sprintf("%sv%d", name, version))
	//3. 写入map
	err = mgr.writeProtoTable(ctx, lbvs.Protocol)
	if err != nil {
		return err
	}
	return nil
}

func (mgr *fwMgr) writeProtoTable(ctx context.Context, table map[uint8]*rule.Bitmap) error {
	var err = mgr.protoTable.CreateTable(ctx)
	if err != nil {
		return err
	}
	for k, v := range table {
		var vv = (*v)[:]
		err = mgr.protoTable.UpdateTable(ctx, []byte{0x08, 0x00, 0x00, 0x00, k}, vv)
		if err != nil {
			return err
		}
	}
	return nil
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
