package bpf

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type ITable interface {
	GCTable(ctx context.Context) error
	CreateTable(ctx context.Context) error
	QueryTable(ctx context.Context) ([]*KV, error)
	DeleteTable(ctx context.Context, key []byte) error
	UpdateTable(ctx context.Context, key []byte, value []byte) error
}

type KV struct {
	Key   []byte `json:"key"`
	Value []byte `json:"Value"`
}

type table struct {
	tYpe       string
	file       string
	keySize    int
	valueSize  int
	maxEntries int
}

func NewTableClient(file string, tYpe string, keySize int, valueSize int, maxEntries int) (ITable, error) {
	//1. 预设类型对应的Flags
	tYpe = strings.ToLower(tYpe)
	switch tYpe {
	case "hash":
	case "array":
	case "lru_hash":
	default:
		return nil, fmt.Errorf("don't support %s map type", tYpe)
	}
	var t = &table{}
	t.file = file
	t.tYpe = tYpe
	t.keySize = keySize
	t.valueSize = valueSize
	t.maxEntries = maxEntries

	return t, nil
}

func (t *table) CreateTable(ctx context.Context) error {
	var ebpf = newBpfTool(
		withExec(),
		withJSON(),
		withMap(),
		withCreateMapCmd(t.file, t.file, t.tYpe, t.keySize, t.valueSize, t.maxEntries),
	)
	var r = make(map[string]interface{})
	var errs = new(bpfErr)
	var err = ebpf.run(ctx, &r, errs)
	if err != nil {
		return err
	}
	if len(errs.Err) > 0 {
		err = errors.New(errs.Err)
	}
	return err
}

func (t *table) UpdateTable(ctx context.Context, key []byte, value []byte) error {
	if len(key) != t.keySize {
		return fmt.Errorf("key len is not %d", t.keySize)
	}
	if len(value) != t.valueSize {
		return fmt.Errorf("value len is not %d", t.valueSize)
	}
	var ebpf = newBpfTool(
		withExec(),
		withJSON(),
		withMap(),
		withUpdateMapCmd(t.file, key, value, "any"),
	)
	var r = make(map[string]interface{})
	var errs = new(bpfErr)
	var err = ebpf.run(ctx, &r, errs)
	if err != nil {
		return err
	}
	if len(errs.Err) > 0 {
		err = errors.New(errs.Err)
	}
	return err
}

func (t *table) QueryTable(ctx context.Context) ([]*KV, error) {
	var ebpf = newBpfTool(
		withExec(),
		withJSON(),
		withMap(),
		withDumpMapCmd(t.file),
	)
	type kv struct {
		Key   []string `json:"key"`
		Value []string `json:"value"`
	}
	type kvList []kv

	var r = new(kvList)
	var errs = new(bpfErr)

	var err = ebpf.run(ctx, r, errs)
	if err != nil {
		return nil, err
	}

	if len(errs.Err) > 0 {
		return nil, errors.New(errs.Err)
	}

	//eg:
	// [{"key":["0x12","0x34","0x56","0x78"],"value":["0x87","0x65","0x43","0x21"]}]
	//
	var rr = make([]*KV, 0, len(*r))
	for i := range *r {
		var v = &KV{
			Key:   make([]byte, t.keySize),
			Value: make([]byte, t.valueSize),
		}
		for ii := range (*r)[i].Key {
			v.Key[ii] = t.hex((*r)[i].Key[ii])
		}
		for ii := range (*r)[i].Value {
			v.Value[ii] = t.hex((*r)[i].Value[ii])
		}
		rr = append(rr, v)
	}
	return rr, nil
}

func (t *table) DeleteTable(ctx context.Context, key []byte) error {
	if len(key) != t.keySize {
		return fmt.Errorf("key len is not %d", t.keySize)
	}
	var ebpf = newBpfTool(
		withExec(),
		withJSON(),
		withMap(),
		withDeleteMapCmd(t.file, key),
	)
	var r = make(map[string]interface{})
	var errs = new(bpfErr)

	var err = ebpf.run(ctx, &r, errs)
	if err != nil {
		return err
	}
	if len(errs.Err) > 0 {
		err = errors.New(errs.Err)
	}
	return err
}

func (t *table) GCTable(ctx context.Context) error {
	var ebpf = newBpfTool()
	return ebpf.unlink(ctx, t.file)
}

func (t *table) hex(s string) byte {
	var v = byte(0)
	//0x12 0xa 12
	for i := len(s) - 1; i >= 0 && s[i] != 'x'; i-- {
		v += byte(s[i]-'0') * byte((len(s) - 1 - i)) * 16
	}
	return v
}
