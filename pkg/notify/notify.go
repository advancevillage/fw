package notify

import (
	"context"
	"errors"

	"github.com/advancevillage/fw/pkg/bpf"
)

type INotifier interface {
	UpdateSecurity(ctx context.Context, value []byte) error
}

var (
	//内核态创建.用户态负责查询和更新
	name     = "iptables"
	nat      = []byte("nat.ptr")
	security = []byte("security.ptr")

	keySize   = int(16)
	valueSize = int(32)
)

type iptables struct {
	tableCli  bpf.ITable
	keySize   int
	valueSize int
}

func NewNotifier() (INotifier, error) {
	var t, err = bpf.NewTableClient(name, "hash", keySize, valueSize, 8)
	if err != nil {
		return nil, err
	}
	return &iptables{
		tableCli:  t,
		keySize:   keySize,
		valueSize: valueSize,
	}, nil
}

func (i *iptables) UpdateSecurity(ctx context.Context, value []byte) error {
	if !i.tableCli.ExistTable(ctx) {
		return errors.New("not load kernel bpf prog")
	}
	return i.updateSecurity(ctx, value)
}

func (i *iptables) update(ctx context.Context, key []byte, value []byte) error {
	if len(key) != i.keySize || len(value) != i.valueSize {
		return errors.New("key size or value size are invalid")
	}
	var err = i.tableCli.UpdateTable(ctx, key, value)
	if err != nil {
		return err
	}
	return nil
}

func (i *iptables) updateSecurity(ctx context.Context, value []byte) error {
	var n = len(value)
	if n > i.valueSize {
		return errors.New("value size is over")
	}
	var kk = make([]byte, i.keySize)
	var vv = make([]byte, i.valueSize)
	copy(kk, security)
	copy(vv, value)
	return i.update(ctx, kk, vv)
}
