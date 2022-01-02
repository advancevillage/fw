package meta

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/fw/pkg/bpf"
	"github.com/advancevillage/fw/proto"
)

var (
	tag    string
	commit string
)

type IMeta interface {
	UpdateZone(ctx context.Context, zone int) error
	QueryMeta(ctx context.Context, table *proto.BpfTable) error
}

var (
	//内核态创建.用户态负责查询和更新
	name      = "metadata"
	fwzone    = []byte("fw.zone")
	fwts      = []byte("fw.ts")
	fwtag     = []byte("fw.tag")
	fwcommit  = []byte("fw.commit")
	bpftag    = []byte("bpf.tag")
	bpfcommit = []byte("bpf.commit")
	bpflpmkey = []byte("bpf.lpmkey")
	bpflpmval = []byte("bpf.lpmval")

	keySize   = int(0x10)
	valueSize = int(0x08)
	maxSize   = int(0x20)
)

type metadata struct {
	tableCli  bpf.ITable
	keySize   int
	valueSize int
	logger    logx.ILogger
}

func NewMetadata(logger logx.ILogger) (IMeta, error) {
	var cli, err = bpf.NewTableClient(logger, name, "hash", keySize, valueSize, maxSize)
	if err != nil {
		return nil, err
	}
	return &metadata{
		tableCli:  cli,
		keySize:   keySize,
		valueSize: valueSize,
		logger:    logger,
	}, nil
}

func (i *metadata) UpdateZone(ctx context.Context, zone int) error {
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

func (i *metadata) ver() (uint64, uint64) {
	tag = strings.Replace(tag, "0x", "", -1)
	commit = strings.Replace(commit, "0x", "", -1)

	a, err := strconv.ParseUint(tag, 16, 64)
	if err != nil {
		a = uint64(0x0)
	}
	b, err := strconv.ParseUint(commit, 16, 64)
	if err != nil {
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

func (i *metadata) QueryMeta(ctx context.Context, table *proto.BpfTable) error {
	if i.tableCli == nil {
		return nil
	}
	if !i.tableCli.ExistTable(ctx) {
		return nil
	}
	var kv, err = i.tableCli.QueryTable(ctx)
	if err != nil {
		return err
	}

	var (
		fwzonek  = make([]byte, i.keySize)
		fwtsk    = make([]byte, i.keySize)
		fwtagk   = make([]byte, i.keySize)
		fwcmitk  = make([]byte, i.keySize)
		bpftagk  = make([]byte, i.keySize)
		bpfcmitk = make([]byte, i.keySize)
		bpflpmkk = make([]byte, i.keySize)
		bpflpmvk = make([]byte, i.keySize)
	)
	copy(fwzonek, fwzone)
	copy(fwtsk, fwts)
	copy(fwtagk, fwtag)
	copy(fwcmitk, fwcommit)
	copy(bpftagk, bpftag)
	copy(bpfcmitk, bpfcommit)
	copy(bpflpmkk, bpflpmkey)
	copy(bpflpmvk, bpflpmval)

	for i := range kv {
		var (
			kk = kv[i].Key
			vv = kv[i].Value
		)
		switch {
		case bytes.Equal(kk, fwzonek):
			zone := uint32(vv[0]) << 24
			zone |= uint32(vv[1]) << 16
			zone |= uint32(vv[2]) << 8
			zone |= uint32(vv[3])
			table.Meta[string(fwzone)] = fmt.Sprintf("%d", zone)
		case bytes.Equal(kk, fwtsk):
			ts := uint64(vv[0]) << 56
			ts |= uint64(vv[1]) << 48
			ts |= uint64(vv[2]) << 40
			ts |= uint64(vv[3]) << 32
			ts |= uint64(vv[4]) << 24
			ts |= uint64(vv[5]) << 16
			ts |= uint64(vv[6]) << 8
			ts |= uint64(vv[7])
			table.Meta[string(fwts)] = fmt.Sprintf("%d", ts)
		case bytes.Equal(kk, fwtagk):
			a := uint16(vv[0]) << 8
			a |= uint16(vv[1])

			b := uint16(vv[2]) << 8
			b |= uint16(vv[3])

			c := uint32(vv[4]) << 24
			c |= uint32(vv[5]) << 16
			c |= uint32(vv[6]) << 8
			c |= uint32(vv[7])

			table.Meta[string(fwtag)] = fmt.Sprintf("%d.%d.%d", a, b, c)
		case bytes.Equal(kk, fwcmitk):
			table.Meta[string(fwcommit)] = hex.EncodeToString(vv)
		case bytes.Equal(kk, bpftagk):
			a := uint16(vv[0]) << 8
			a |= uint16(vv[1])

			b := uint16(vv[2]) << 8
			b |= uint16(vv[3])

			c := uint32(vv[4]) << 24
			c |= uint32(vv[5]) << 16
			c |= uint32(vv[6]) << 8
			c |= uint32(vv[7])

			table.Meta[string(bpftag)] = fmt.Sprintf("%d.%d.%d", a, b, c)
		case bytes.Equal(kk, bpfcmitk):
			table.Meta[string(bpfcommit)] = hex.EncodeToString(vv)
		case bytes.Equal(kk, bpflpmkk):
			lpmkey := uint64(vv[0]) << 56
			lpmkey |= uint64(vv[1]) << 48
			lpmkey |= uint64(vv[2]) << 40
			lpmkey |= uint64(vv[3]) << 32
			lpmkey |= uint64(vv[4]) << 24
			lpmkey |= uint64(vv[5]) << 16
			lpmkey |= uint64(vv[6]) << 8
			lpmkey |= uint64(vv[7])
			table.Meta[string(bpflpmkey)] = fmt.Sprintf("%d", lpmkey)
		case bytes.Equal(kk, bpflpmvk):
			lpmval := uint64(vv[0]) << 56
			lpmval |= uint64(vv[1]) << 48
			lpmval |= uint64(vv[2]) << 40
			lpmval |= uint64(vv[3]) << 32
			lpmval |= uint64(vv[4]) << 24
			lpmval |= uint64(vv[5]) << 16
			lpmval |= uint64(vv[6]) << 8
			lpmval |= uint64(vv[7])
			table.Meta[string(bpflpmval)] = fmt.Sprintf("%d", lpmval)
		}
	}
	return nil
}
