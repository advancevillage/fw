package bpf

import (
	"context"
	"encoding/binary"
	"testing"
)

var testDumpMap = map[string]struct {
	name string
}{
	"case1": {},
}

func Test_run_map(t *testing.T) {
	var cmd = "show"
	var b = newBpfTool(withExec(), withJSON(), withMap(), withCmd(cmd))
	for n := range testDumpMap {
		f := func(t *testing.T) {
			var bms = new(bpfMaps)
			var bes = new(bpfErrs)
			var err = b.run(context.TODO(), bms, bes)
			t.Log(*bms)
			t.Log(*bes)
			if err != nil {
				t.Fatal(err)
				return
			}
		}
		t.Run(n, f)
	}

}

var testOpMap = map[string]struct {
	name      string
	file      string
	tYpe      string
	keySize   int
	valueSize int
	max       int
}{
	"case1": {
		name:      "xxx",
		file:      "abc",
		tYpe:      "hash",
		keySize:   4,
		valueSize: 4,
		max:       64,
	},
}

func Test_op_map(t *testing.T) {
	for n, p := range testOpMap {
		var b = newBpfTool(withExec(), withJSON(), withMap(), withCreateMapCmd(p.name, p.file, p.tYpe, p.keySize, p.valueSize, p.max))
		f := func(t *testing.T) {
			var bms = new(bpfMap)
			var bes = new(bpfErr)
			var err = b.run(context.TODO(), bms, bes)
			t.Log("create", bms, err)
			t.Log("create", bes, err)
			if err != nil {
				t.Fatal(err)
				return
			}

			var (
				key   = make([]byte, 4)
				value = make([]byte, 4)
			)
			binary.BigEndian.PutUint32(key, 0x12345678)
			binary.BigEndian.PutUint32(value, 0x87654321)
			withUpdateMapCmd(p.file, key, value, UpdateFlagAny)(b)
			err = b.run(context.TODO(), bms, bes)
			t.Log("update", bms, err)
			t.Log("update", bes, err)
			if err != nil {
				t.Fatal(err)
				return
			}

			withDumpMapCmd(p.file)(b)
			type item struct {
				Key   []string `json:"key"`
				Value []string `json:"value"`
			}
			type items []item
			var entries = new(items)
			var errs = new(bpfErrs)
			err = b.run(context.TODO(), entries, errs)
			t.Log("dump", entries, err)
			t.Log("dump", errs, err)
			if err != nil {
				t.Fatal(err)
				return
			}
		}
		t.Run(n, f)
	}

}
