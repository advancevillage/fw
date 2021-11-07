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
			for _, v := range act {
				fmt.Printf("%d %d %d %d %d %d %d %d %d %d\n", v.Protocol, v.SrcIp, v.SrcIpMask, v.SrcPort, v.SrcPortMask, v.DstIp, v.DstIpMask, v.DstPort, v.DstPortMask, v.Action)
			}
			var lbvs = s.analyze(act)
			fmt.Println(*lbvs)
		}
		t.Run(n, f)

	}

}
