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
}{
	"case1": {
		name:    randStr(8),
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
			err = s.Clean(ctx, p.name, p.version)
			if err != nil {
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
