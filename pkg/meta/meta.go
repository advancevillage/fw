package meta

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/advancevillage/fw/pkg/bpf"
)

var (
	tag    string
	commit string
)

type IMeta interface {
	UpdateMetaFwZone(ctx context.Context, zone int) error
	Version() (uint64, uint64)
}

var (
	//内核态创建.用户态负责查询和更新
	name     = "metadata"
	fwzone   = []byte("fw.zone")
	fwts     = []byte("fw.ts")
	fwtag    = []byte("fw.tag")
	fwcommit = []byte("fw.commit")

	keySize   = int(0x10)
	valueSize = int(0x08)
	maxSize   = int(0x20)
)

type metadata struct {
	tableCli  bpf.ITable
	keySize   int
	valueSize int
}

func NewMetadata() (IMeta, error) {
	var cli, err = bpf.NewTableClient(name, "hash", keySize, valueSize, maxSize)
	if err != nil {
		return nil, err
	}
	return &metadata{
		tableCli:  cli,
		keySize:   keySize,
		valueSize: valueSize,
	}, nil
}

func (i *metadata) UpdateMetaFwZone(ctx context.Context, zone int) error {
	i.meta(ctx)

	var kk = make([]byte, i.keySize)
	var vv = make([]byte, i.valueSize)
	copy(kk, []byte(fwzone))
	vv[0x00] = uint8(zone >> 24)
	vv[0x01] = uint8(zone >> 16)
	vv[0x02] = uint8(zone >> 8)
	vv[0x03] = uint8(zone)
	vv[0x04] = 0x00
	vv[0x05] = 0x00
	vv[0x06] = 0x00
	vv[0x07] = 0x00
	var err = i.update(ctx, kk, vv)
	if err != nil {
		return err
	}
	return nil
}

func (i *metadata) Version() (uint64, uint64) {
	return i.ver()
}

func (i *metadata) ver() (uint64, uint64) {
	tag = strings.Replace(tag, "0x", "", -1)
	commit = strings.Replace(commit, "0x", "", -1)

	a, err := strconv.ParseUint(tag, 16, 64)
	if err != nil {
		fmt.Println(tag, err)
		a = uint64(0x0)
	}
	b, err := strconv.ParseUint(commit, 16, 64)
	if err != nil {
		fmt.Println(commit, err)
		b = uint64(0x0)
	}
	return a, b
}

func (i *metadata) meta(ctx context.Context) {
	var kk = make([]byte, i.keySize)
	var vv = make([]byte, i.valueSize)
	var now = time.Now().Unix()
	var tag, commit = i.ver()
	//1. meta tag
	copy(kk, []byte(fwtag))
	vv[0x00] = uint8(tag >> 56)
	vv[0x01] = uint8(tag >> 48)
	vv[0x02] = uint8(tag >> 40)
	vv[0x03] = uint8(tag >> 32)
	vv[0x04] = uint8(tag >> 24)
	vv[0x05] = uint8(tag >> 16)
	vv[0x06] = uint8(tag >> 8)
	vv[0x07] = uint8(tag)
	i.update(ctx, kk, vv)

	//2. meta commit
	for n := 0; n < i.keySize; n++ {
		kk[n] = 0x00
	}
	copy(kk, []byte(fwcommit))
	vv[0x00] = uint8(commit >> 56)
	vv[0x01] = uint8(commit >> 48)
	vv[0x02] = uint8(commit >> 40)
	vv[0x03] = uint8(commit >> 32)
	vv[0x04] = uint8(commit >> 24)
	vv[0x05] = uint8(commit >> 16)
	vv[0x06] = uint8(commit >> 8)
	vv[0x07] = uint8(commit)
	i.update(ctx, kk, vv)

	//3. meta ts
	for n := 0; n < i.keySize; n++ {
		kk[n] = 0x00
	}
	copy(kk, []byte(fwts))
	vv[0x00] = uint8(now >> 56)
	vv[0x01] = uint8(now >> 48)
	vv[0x02] = uint8(now >> 40)
	vv[0x03] = uint8(now >> 32)
	vv[0x04] = uint8(now >> 24)
	vv[0x05] = uint8(now >> 16)
	vv[0x06] = uint8(now >> 8)
	vv[0x07] = uint8(now)
	i.update(ctx, kk, vv)
}

func (i *metadata) update(ctx context.Context, key []byte, value []byte) error {
	var err error
	if !i.tableCli.ExistTable(ctx) {
		err = i.tableCli.CreateTable(ctx)
	}
	if err != nil {
		return err
	}
	if len(key) != i.keySize {
		return errors.New("key size is invalid")
	}
	if len(value) != i.valueSize {
		return errors.New("value size is invalid")
	}
	err = i.tableCli.UpdateTable(ctx, key, value)
	if err != nil {
		return err
	}
	return nil
}
