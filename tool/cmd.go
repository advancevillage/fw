package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/advancevillage/fw/pkg/rule"
)

type cmdArgs struct {
	get  string //-g
	help bool   //-h

	left  int //-l
	right int //-r
	num   int //--num
	ip    string
}

var (
	cmdargs = &cmdArgs{}
)

func init() {
	flag.StringVar(&cmdargs.get, "g", "", "Get info")
	flag.StringVar(&cmdargs.get, "get", "", "Get info")
	flag.BoolVar(&cmdargs.help, "h", false, "Help message")
	flag.BoolVar(&cmdargs.help, "help", false, "Help message")
	flag.IntVar(&cmdargs.num, "num", 0, "Number")
	flag.IntVar(&cmdargs.num, "number", 0, "Number")
	flag.IntVar(&cmdargs.left, "l", 0, "Left Of []")
	flag.IntVar(&cmdargs.left, "left", 0, "Left Of []")
	flag.IntVar(&cmdargs.right, "r", 0, "Right Of []")
	flag.IntVar(&cmdargs.right, "right", 0, "Right Of []")
	flag.StringVar(&cmdargs.ip, "ip", "0.0.0.0", "IP")

	flag.Usage = func() {
		fmt.Printf("\n%s", errHelpMsg)
	}
}
func main() {
	if !flag.Parsed() {
		flag.Parse()
	}

	if len(os.Args) == 1 {
		usage()
		return
	}

	if cmdargs.help {
		help(cmdargs)
		return
	}
	if err := cmdargs.parse(); err != nil {
		errHelp("ERROR: %v\n", err)
		return
	}
	cmdargs.run()
}

func (c *cmdArgs) parse() error {
	//1: 解析IP
	if nil == net.ParseIP(c.ip) {
		return errors.New("ip format")
	}
	switch c.get {
	case "port_mask":
	case "hex":
	case "dec":
	default:
		return errors.New("don't support get-type")
	}
	return nil
}

func (c *cmdArgs) run() {
	switch c.get {
	case "port_mask":
		var l = c.left
		var r = c.right
		if l < 0 {
			l = 0
		}
		if l > 65535 {
			l = 65535
		}
		if r < 0 {
			r = 0
		}
		if r > 65535 {
			r = 65535
		}
		pmask, _ := rule.NewPortMask(l, r)
		for _, v := range pmask {
			fmt.Printf("\t0x%04x/%d\t\n", v.Port, v.Mask)
		}
	case "hex":
		if c.ip != "0.0.0.0" && len(c.ip) > 0 {
			l := strings.Split(c.ip, ".")
			a, _ := strconv.Atoi(l[0])
			b, _ := strconv.Atoi(l[1])
			c, _ := strconv.Atoi(l[2])
			d, _ := strconv.Atoi(l[3])
			fmt.Printf("\t0x%02x%02x%02x%02x\t\n", a, b, c, d)
		} else {
			fmt.Printf("\t0x%x\t\n", c.num)
		}
	case "dec":
	}
}

func usage() {
	fmt.Println(usageHelpMsg)
}

func help(args *cmdArgs) {
	if args.get != "" {
		switch args.get {
		case "port_mask":
			fmt.Println(portMaskHelp)
		case "hex":
			fmt.Println(hexHelp)
		case "dec":
			fmt.Println(decHelp)
		}
		return
	}
	usage()
}

func errHelp(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%s%s", msg, errHelpMsg)
}
