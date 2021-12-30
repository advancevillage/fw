package fw

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/fw/proto"
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
		}
		t.Run(n, f)
	}

}
