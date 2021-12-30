package fw

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/fw/proto"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().Unix())
}

var writeTestData = map[string]struct {
	version int
	rules   []*proto.FwRule
}{
	"case1": {
		version: 0,
		rules: []*proto.FwRule{
			{
				Protocol: "tcp",
				SrcIp:    "192.168.56.1/24",
				DstIp:    "0.0.0.0/0",
				DstPort:  "1-65535",
				Action:   "accept",
			},
			{
				Protocol: "udp",
				SrcIp:    "192.168.56.1/24",
				DstIp:    "0.0.0.0/0",
				DstPort:  "1-65535",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				DstIp:    "110.11.11.24/32",
				DstPort:  "22",
				Action:   "accept",
			},
			{
				Protocol: "udp",
				SrcIp:    "114.114.114.114/24",
				SrcPort:  "1-65535",
				DstIp:    "8.8.8.8/32",
				DstPort:  "22-222",
				Action:   "drop",
			},
		},
	},
}

func Test_write(t *testing.T) {
	logger, err := logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	s, err := NewFwMgr(logger, 4)
	if err != nil {
		t.Fatal(err)
		return
	}
	for n, p := range writeTestData {
		f := func(t *testing.T) {
			var ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err = s.Write(ctx, p.version, p.rules)
			if err != nil {
				t.Fatal(err)
				return
			}
			ss, ok := (s).(*fwMgr)
			if ok {
				ss.protoTable.GCTable(ctx)
				ss.actionTable.GCTable(ctx)
				ss.srcIpTable.GCTable(ctx)
				ss.srcPortTable.GCTable(ctx)
				ss.dstIpTable.GCTable(ctx)
				ss.dstPortTable.GCTable(ctx)
			}
		}
		t.Run(n, f)
	}

}

var portMergeTest = map[string]struct {
	rule []*proto.FwRule
	exp  []*proto.FwRule
}{
	"case1": {
		rule: []*proto.FwRule{
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-32767",
				DstPort:  "22-23",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-32767",
				DstPort:  "24-31",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-32767",
				DstPort:  "32-63",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-32767",
				DstPort:  "64-95",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-32767",
				DstPort:  "96-99",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-32767",
				DstPort:  "100-100",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "32768-65535",
				DstPort:  "22-23",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "32768-65535",
				DstPort:  "24-31",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "32768-65535",
				DstPort:  "32-63",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "32768-65535",
				DstPort:  "64-95",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "32768-65535",
				DstPort:  "96-99",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "32768-65535",
				DstPort:  "100-100",
				Action:   "accept",
			},
			{
				Protocol: "icmp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-0",
				DstPort:  "0-0",
				Action:   "accept",
			},
			{
				Protocol: "icmp",
				SrcIp:    "112.80.248.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-0",
				DstPort:  "0-0",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "0-32767",
				DstPort:  "443-443",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				SrcPort:  "32768-65535",
				DstPort:  "443-443",
				Action:   "accept",
			},
		},
		exp: []*proto.FwRule{
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				DstPort:  "22-100",
				Action:   "accept",
			},
			{
				Protocol: "tcp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				DstPort:  "443",
				Action:   "accept",
			},
			{
				Protocol: "icmp",
				SrcIp:    "112.80.248.0/24",
				DstIp:    "10.10.2.0/24",
				Action:   "accept",
			},
			{
				Protocol: "icmp",
				SrcIp:    "10.10.2.0/24",
				DstIp:    "10.10.2.0/24",
				Action:   "accept",
			},
		},
	},
}

func Test_port_merge(t *testing.T) {
	var logger, err = logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	var s = &fwMgr{logger: logger}
	for n, p := range portMergeTest {
		f := func(t *testing.T) {
			act := s.portMerge(context.TODO(), p.rule)
			equal(t, p.exp, act)
		}
		t.Run(n, f)
	}
}

func equal(t *testing.T, a []*proto.FwRule, b []*proto.FwRule) {
	var m = make(map[string]bool)
	for _, v := range a {
		m[fmt.Sprintf("%s%s%s%s%s%s", v.Protocol, v.SrcIp, v.SrcPort, v.DstIp, v.DstPort, v.Action)] = true
	}
	var n = make(map[string]bool)
	for _, v := range b {
		n[fmt.Sprintf("%s%s%s%s%s%s", v.Protocol, v.SrcIp, v.SrcPort, v.DstIp, v.DstPort, v.Action)] = true
	}
	assert.Equal(t, m, n)
}
