package rule

import (
	"fmt"
	"testing"

	"github.com/advancevillage/fw/proto"
)

var testEngine = map[string]struct {
	rules []*proto.FwRule
}{
	"case1": {
		rules: []*proto.FwRule{
			{
				Protocol: "tcp",
				DstIp:    "110.11.11.24/32",
				DstPort:  "22",
				Action:   "accept",
			},
		},
	},
	"case2": {
		rules: []*proto.FwRule{
			{
				Protocol: "udp",
				SrcIp:    "1.1.1.1/32",
				SrcPort:  "100-200",
				DstIp:    "110.11.11.24/32",
				DstPort:  "22",
				Action:   "accept",
			},
		},
	},
	"case3": {
		rules: []*proto.FwRule{
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
				Action:   "accept",
			},
		},
	},
}

func Test_engine(t *testing.T) {
	var s = engine{}
	for n, p := range testEngine {
		f := func(t *testing.T) {
			var act, err = s.parse(p.rules)
			if err != nil {
				t.Fatal(err)
				return
			}
			for i, v := range act {
				fmt.Printf("#%d %d %d %d %d %d %d %d %d %d %d\n", i, v.Protocol, v.SrcIp, v.SrcIpMask, v.SrcPort, v.SrcPortMask, v.DstIp, v.DstIpMask, v.DstPort, v.DstPortMask, v.Action)
			}
			var lbvs = s.analyze(act)
			t.Log(lbvs)
		}
		t.Run(n, f)

	}

}
