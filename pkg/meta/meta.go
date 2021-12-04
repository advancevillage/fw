package meta

import (
	"context"
	"errors"

	"github.com/advancevillage/fw/pkg/bpf"
)

type IMeta interface {
	UpdateMetaFwProto(ctx context.Context, name string) error
	UpdateMetaFwAction(ctx context.Context, name string) error
	UpdateMetaFwSrcIp(ctx context.Context, name string) error
	UpdateMetaFwSrcPort(ctx context.Context, name string) error
	UpdateMetaFwDstIp(ctx context.Context, name string) error
	UpdateMetaFwDstPort(ctx context.Context, name string) error
	GC(ctx context.Context)
}

var (
	//内核态创建.用户态负责查询和更新
	name      = "metadata"
	fwproto   = []byte("fw.proto")
	fwsrcip   = []byte("fw.srcip")
	fwsrcport = []byte("fw.srcport")
	fwdstip   = []byte("fw.dstip")
	fwdstport = []byte("fw.dstport")
	fwaction  = []byte("fw.action")

	keySize   = int(0x10)
	valueSize = int(0x04)
	maxSize   = int(0x20)
)

type metadata struct {
	tableCli  bpf.ITable
	keySize   int
	valueSize int
}

func NewMetadata() (IMeta, error) {
	var t, err = bpf.NewTableClient(name, "hash_of_maps", keySize, valueSize, maxSize)
	if err != nil {
		return nil, err
	}
	return &metadata{
		tableCli:  t,
		keySize:   keySize,
		valueSize: valueSize,
	}, nil
}

func (i *metadata) UpdateMetaFwProto(ctx context.Context, name string) error {
	return i.updateMeta(ctx, fwproto, name)
}

func (i *metadata) UpdateMetaFwSrcIp(ctx context.Context, name string) error {
	return i.updateMeta(ctx, fwsrcip, name)
}

func (i *metadata) UpdateMetaFwSrcPort(ctx context.Context, name string) error {
	return i.updateMeta(ctx, fwsrcport, name)
}

func (i *metadata) UpdateMetaFwDstIp(ctx context.Context, name string) error {
	return i.updateMeta(ctx, fwdstip, name)
}

func (i *metadata) UpdateMetaFwDstPort(ctx context.Context, name string) error {
	return i.updateMeta(ctx, fwdstport, name)
}

func (i *metadata) UpdateMetaFwAction(ctx context.Context, name string) error {
	return i.updateMeta(ctx, fwaction, name)
}

func (i *metadata) GC(ctx context.Context) {
	i.tableCli.GCTable(ctx)
}

func (i *metadata) updateMeta(ctx context.Context, key []byte, name string) error {
	var kk = make([]byte, i.keySize)
	copy(kk, key)
	return i.update(ctx, kk, name)
}

func (i *metadata) update(ctx context.Context, key []byte, name string) error {
	var err error
	if !i.tableCli.ExistTable(ctx) {
		err = i.tableCli.CreateMapInMapTable(ctx, name)
	}
	if err != nil {
		return err
	}
	if len(key) != i.keySize {
		return errors.New("key size is invalid")
	}
	err = i.tableCli.UpdateMapInMapTable(ctx, key, name)
	if err != nil {
		return err
	}
	return nil
}
