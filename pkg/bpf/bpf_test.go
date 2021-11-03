package bpf

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

var testTable = map[string]struct {
	file       string
	tYpe       string
	keySize    int
	valueSize  int
	maxEntries int
}{
	"case1": {
		file:       "nikjkl",
		tYpe:       "hash",
		keySize:    4,
		valueSize:  4,
		maxEntries: 64,
	},
}

func Test_table(t *testing.T) {
	for n, p := range testTable {
		f := func(t *testing.T) {
			var ta, err = NewTableClient(p.file, p.tYpe, p.keySize, p.valueSize, p.maxEntries)
			if err != nil {
				t.Fatal(err)
				return
			}
			//1. 创建表
			var ctx, cancel = context.WithTimeout(context.Background(), time.Second*20)
			defer cancel()

			err = ta.CreateTable(ctx)
			if err != nil {
				t.Fatal("create table fail", err)
				return
			}
			//2. 准备数据
			var data = make([]*KV, 0, p.maxEntries)
			for i := 0; i < p.maxEntries; i++ {
				data = append(data, &KV{
					Key:   []byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
					Value: []byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))},
				})
			}
			//3. 更新数据
			for _, v := range data {
				err = ta.UpdateTable(ctx, v.Key, v.Value)
				if err != nil {
					t.Fatal(err)
					return
				}
			}
			//4. 查询
			act, err := ta.QueryTable(ctx)
			if err != nil {
				t.Fatal(err)
				return
			}
			fmt.Println(act)
			//n. 回收表
			//err = ta.GCTable(ctx)
			//if err != nil {
			//	t.Fatal("gc table fail", err)
			//	return
			//}
		}
		t.Run(n, f)
	}
}
