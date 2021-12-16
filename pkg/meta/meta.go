package meta

import (
	"context"
	"errors"
	"time"

	"github.com/advancevillage/fw/pkg/bpf"
)

var (
	tag    = uint64(0)
	commit = uint64(0)
)

type IMeta interface {
	UpdateMetaFwZone(ctx context.Context, zone int) error
}

var (
	//内核态创建.用户态负责查询和更新
	name   = "metadata"
	fwzone = []byte("fw.zone")
	fwts   = []byte("fw.ts")

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
	var kk = make([]byte, i.keySize)
	var vv = make([]byte, i.valueSize)
	var now = time.Now().Unix()
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
	err = i.update(ctx, kk, vv)
	if err != nil {
		return err
	}
	return nil
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
