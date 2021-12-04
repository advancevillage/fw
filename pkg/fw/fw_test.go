package fw

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/advancevillage/fw/proto"
)

func init() {
	rand.Seed(time.Now().Unix())
}

var writeTestData = map[string]struct {
	name    string
	version int
	rules   []*proto.FwRule
	debug   bool
}{
	"case1": {
		name:    randStr(4),
		version: 0,
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
				Action:   "drop",
			},
		},
		debug: true,
	},
}

func Test_write(t *testing.T) {
	var s, err = NewFwMgr(4)
	if err != nil {
		t.Fatal(err)
		return
	}
	for n, p := range writeTestData {
		f := func(t *testing.T) {
			var ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = s.Write(ctx, p.name, p.version, p.rules)
			if err != nil && !p.debug {
				t.Fatal(err)
				return
			}
			err = s.Clean(ctx, p.name, p.version)
			if err != nil && !p.debug {
				t.Fatal(err)
				return
			}
		}
		t.Run(n, f)
	}

}

func randStr(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
	for i := 0; i < length; i++ {
		result = append(result, bytes[rand.Intn(len(bytes))])
	}
	return string(result)
}
