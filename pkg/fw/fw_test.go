package fw

import (
	"context"
	"testing"
	"time"

	"github.com/advancevillage/fw/proto"
)

var writeTestData = map[string]struct {
	name    string
	version int
	rules   []*proto.FwRule
}{
	"case1": {
		name:    "UpDown",
		version: 0,
		rules: []*proto.FwRule{
			{
				Protocol: "tcp",
				DstIp:    "110.11.11.24/32",
				DstPort:  "22",
				Action:   "accept",
			},
		},
	},
}

func Test_write(t *testing.T) {
	var s, err = NewFwMgr()
	if err != nil {
		t.Fatal(err)
		return
	}
	for n, p := range writeTestData {
		f := func(t *testing.T) {
			var ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = s.Write(ctx, p.name, p.version, p.rules)
			if err != nil {
				t.Fatal(err)
				return
			}
		}
		t.Run(n, f)
	}

}
