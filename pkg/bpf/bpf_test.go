package bpf

import (
	"context"
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
		file:       "pin-1",
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

			//n. 回收表
			err = ta.GCTable(ctx)
			if err != nil {
				t.Fatal("gc table fail", err)
				return
			}
		}
		t.Run(n, f)
	}
}
