package bpf

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"
)

const (
	BPFFS = "/sys/fs/bpf"
)

type bpftool struct {
	exec    string
	options string
	object  string
	cmd     string
}

type bpftoolOption func(*bpftool)

func newBpfTool(opts ...bpftoolOption) *bpftool {
	var a = new(bpftool)

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func withExec() bpftoolOption {
	return func(a *bpftool) {
		a.exec = "bpftool"
	}
}

func withJSON() bpftoolOption {
	return func(a *bpftool) {
		a.options = strings.Trim(fmt.Sprintf("%s %s", a.options, "-j"), " ")
	}
}

func withMap() bpftoolOption {
	return func(a *bpftool) {
		a.object = "map"
	}
}

func withCmd(cmd string) bpftoolOption {
	return func(a *bpftool) {
		a.cmd = strings.Trim(cmd, " ")
	}
}

func withCreateMapCmd(name string, file string, tYpe string, keySize int, valueSize int, entries int) bpftoolOption {
	//mount bpffs /sys/fs/bpf -t bpf
	file = fmt.Sprintf("%s/%s", BPFFS, file)
	var cmd = fmt.Sprintf("create %s type %s key %d value %d entries %d name %s", file, tYpe, keySize, valueSize, entries, name)
	return withCmd(cmd)
}

func withDumpMapCmd(file string) bpftoolOption {
	file = fmt.Sprintf("%s/%s", BPFFS, file)
	var cmd = fmt.Sprintf("dump pinned %s", file)
	return withCmd(cmd)
}

func withLookUpMapCmd(file string, key []byte) bpftoolOption {
	file = fmt.Sprintf("%s/%s", BPFFS, file)
	var cmd = fmt.Sprintf("lookup pinned %s key hex", file)

	for i := range key {
		cmd = fmt.Sprintf("%s %x", cmd, key[i])
	}

	return withCmd(cmd)
}

func withDeleteMapCmd(file string, key []byte) bpftoolOption {
	file = fmt.Sprintf("%s/%s", BPFFS, file)
	var cmd = fmt.Sprintf("delete pinned %s key hex", file)

	for i := range key {
		cmd = fmt.Sprintf("%s %x", cmd, key[i])
	}

	return withCmd(cmd)
}

func withNextKeyMapCmd(file string, key []byte) bpftoolOption {
	file = fmt.Sprintf("%s/%s", BPFFS, file)
	var cmd = fmt.Sprintf("getnext pinned %s key hex", file)

	for i := range key {
		cmd = fmt.Sprintf("%s %x", cmd, key[i])
	}

	return withCmd(cmd)
}

func withUpdateMapCmd(file string, key []byte, value []byte, flag string) bpftoolOption {
	file = fmt.Sprintf("%s/%s", BPFFS, file)
	var cmd = fmt.Sprintf("update pinned %s key hex", file)

	for i := range key {
		cmd = fmt.Sprintf("%s %x", cmd, key[i])
	}

	cmd = fmt.Sprintf("%s value hex", cmd)

	for i := range value {
		cmd = fmt.Sprintf("%s %x", cmd, value[i])
	}

	cmd = fmt.Sprintf("%s %s", cmd, flag)

	return withCmd(cmd)
}

func (a *bpftool) run(ctx context.Context, reply interface{}, errs interface{}) error {
	var (
		args   = fmt.Sprintf("%s %s %s", a.options, a.object, a.cmd)
		cmd    = exec.CommandContext(ctx, a.exec, strings.Split(args, " ")...)
		stdOut io.ReadCloser
		buf    []byte
		err    error
	)
	fmt.Println(cmd.String())
	stdOut, err = cmd.StdoutPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		return err
	}
	var r = bufio.NewReader(stdOut)
	buf, err = ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	//注意:  bpftool map 增加   删除   更新   查询
	//成功:				 null   null    null   array
	//失败:              object object  object array
	//示例:
	//
	if json.Valid(buf) {
		err = json.Unmarshal(buf, reply)
		if err != nil {
			return err
		}
		err = json.Unmarshal(buf, errs)
		if err != nil {
			return err
		}
	}
	err = cmd.Wait()
	if err != nil {
		return err
	}
	return nil
}

func (a *bpftool) unlink(ctx context.Context, file string) error {
	file = fmt.Sprintf("%s/%s", BPFFS, file)
	var cmd = exec.CommandContext(ctx, "unlink", file)
	var err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
