package rule

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/advancevillage/fw/proto"
)

var (
	bml = uint16(8)
)

var testEngine = map[string]struct {
	rules []*proto.FwRule
	lbvs  *LBVS
}{
	"case-no-srcIp-srcPort-1-rule": {
		rules: []*proto.FwRule{
			{
				Protocol: "tcp",
				DstIp:    "110.11.11.24/32",
				DstPort:  "22",
				Action:   "accept",
			},
		},
		lbvs: &LBVS{
			Protocol: map[string]IBitmap{
				ProtoMaskEncode(&ProtoMask{Proto: number["tcp"], Mask: 0x08}): via(0),
			},
			SrcIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0, Mask: 0}): via(0),
			},
			SrcPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0, Mask: 0}): via(0),
			},
			DstIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x6e0b0b18, Mask: 0x20}): via(0),
			},
			DstPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x16, Mask: 0x10}): via(0),
			},
			Action: map[string]IBitmap{
				ActionMaskEncode(&ActionMask{Action: 0x01, Mask: 0x08}): via(0),
			},
		},
	},
	"case-no-srcIp-1-rule": {
		rules: []*proto.FwRule{
			{
				Protocol: "tcp",
				SrcIp:    "0.0.0.0/32",
				SrcPort:  "44",
				DstIp:    "110.11.11.24/32",
				DstPort:  "22",
				Action:   "accept",
			},
		},
		lbvs: &LBVS{
			Protocol: map[string]IBitmap{
				ProtoMaskEncode(&ProtoMask{Proto: number["tcp"], Mask: 0x08}): via(0),
			},
			SrcIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0, Mask: 0x20}): via(0),
			},
			SrcPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x2c, Mask: 0x10}): via(0),
			},
			DstIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x6e0b0b18, Mask: 0x20}): via(0),
			},
			DstPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x16, Mask: 0x10}): via(0),
			},
			Action: map[string]IBitmap{
				ActionMaskEncode(&ActionMask{Action: 0x01, Mask: 0x08}): via(0),
			},
		},
	},
	"case-no-dstIp-seg-1-rule": {
		rules: []*proto.FwRule{
			{
				Protocol: "tcp",
				SrcIp:    "0.0.0.0/32",
				SrcPort:  "44",
				DstIp:    "110.11.11.24/24",
				DstPort:  "22",
				Action:   "accept",
			},
		},
		lbvs: &LBVS{
			Protocol: map[string]IBitmap{
				ProtoMaskEncode(&ProtoMask{Proto: number["tcp"], Mask: 0x08}): via(0),
			},
			SrcIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0, Mask: 0x20}): via(0),
			},
			SrcPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x2c, Mask: 0x10}): via(0),
			},
			DstIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x6e0b0b00, Mask: 0x18}): via(0),
			},
			DstPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x16, Mask: 0x10}): via(0),
			},
			Action: map[string]IBitmap{
				ActionMaskEncode(&ActionMask{Action: 0x01, Mask: 0x08}): via(0),
			},
		},
	},
	"case-no-srcIp-seg-1-rule": {
		rules: []*proto.FwRule{
			{
				Protocol: "tcp",
				SrcIp:    "0.0.0.0/24",
				SrcPort:  "44",
				DstIp:    "110.11.11.24/24",
				DstPort:  "22",
				Action:   "accept",
			},
		},
		lbvs: &LBVS{
			Protocol: map[string]IBitmap{
				ProtoMaskEncode(&ProtoMask{Proto: number["tcp"], Mask: 0x08}): via(0),
			},
			SrcIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0, Mask: 0x18}): via(0),
			},
			SrcPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x2c, Mask: 0x10}): via(0),
			},
			DstIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x6e0b0b00, Mask: 0x18}): via(0),
			},
			DstPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x16, Mask: 0x10}): via(0),
			},
			Action: map[string]IBitmap{
				ActionMaskEncode(&ActionMask{Action: 0x01, Mask: 0x08}): via(0),
			},
		},
	},
	"case-mulit-srcPort": {
		rules: []*proto.FwRule{
			{
				Protocol: "udp",
				SrcIp:    "1.1.1.1/32",
				//	0x0064/14
				//	0x0068/13
				//	0x0070/12
				//	0x0080/10
				//	0x00c0/13
				//	0x00c8/16
				SrcPort: "100-200",
				DstIp:   "110.11.11.24/32",
				DstPort: "22",
				Action:  "drop",
			},
		},
		lbvs: &LBVS{
			Protocol: map[string]IBitmap{
				ProtoMaskEncode(&ProtoMask{Proto: number["udp"], Mask: 0x08}): via(0, 1, 2, 3, 4, 5),
			},
			SrcIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x01010101, Mask: 0x20}): via(0, 1, 2, 3, 4, 5),
			},
			SrcPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x0064, Mask: 0x0e}): via(0),
				PortMaskEncode(&PortMask{Port: 0x0068, Mask: 0x0d}): via(1),
				PortMaskEncode(&PortMask{Port: 0x0070, Mask: 0x0c}): via(2),
				PortMaskEncode(&PortMask{Port: 0x0080, Mask: 0x0a}): via(3),
				PortMaskEncode(&PortMask{Port: 0x00c0, Mask: 0x0d}): via(4),
				PortMaskEncode(&PortMask{Port: 0x00c8, Mask: 0x10}): via(5),
			},
			DstIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x6e0b0b18, Mask: 0x20}): via(0, 1, 2, 3, 4, 5),
			},
			DstPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x16, Mask: 0x10}): via(0, 1, 2, 3, 4, 5),
			},
			Action: map[string]IBitmap{
				ActionMaskEncode(&ActionMask{Action: 0x00, Mask: 0x08}): via(0, 1, 2, 3, 4, 5),
			},
		},
	},
	"case-mulit-srcPort2": {
		rules: []*proto.FwRule{
			{
				Protocol: "udp",
				SrcIp:    "1.1.1.1/32",
				//	0x0064/14
				//	0x0068/13
				//	0x0070/12
				//	0x0080/10
				//	0x00c0/13
				//	0x00c8/16
				SrcPort: "100-200",
				DstIp:   "110.11.11.24/32",
				DstPort: "22",
				Action:  "drop",
			},
			{
				Protocol: "tcp",
				SrcIp:    "1.1.1.1/32",
				//	0x0078/16
				SrcPort: "120",
				DstIp:   "110.11.11.24/32",
				DstPort: "22",
				Action:  "accept",
			},
		},
		lbvs: &LBVS{
			Protocol: map[string]IBitmap{
				ProtoMaskEncode(&ProtoMask{Proto: number["udp"], Mask: 0x08}): via(0, 1, 2, 3, 4, 5),
				ProtoMaskEncode(&ProtoMask{Proto: number["tcp"], Mask: 0x08}): via(6),
			},
			SrcIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x01010101, Mask: 0x20}): via(0, 1, 2, 3, 4, 5, 6),
			},
			SrcPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x0064, Mask: 0x0e}): via(0),
				PortMaskEncode(&PortMask{Port: 0x0068, Mask: 0x0d}): via(1),
				PortMaskEncode(&PortMask{Port: 0x0070, Mask: 0x0c}): via(2, 6),
				PortMaskEncode(&PortMask{Port: 0x0080, Mask: 0x0a}): via(3),
				PortMaskEncode(&PortMask{Port: 0x00c0, Mask: 0x0d}): via(4),
				PortMaskEncode(&PortMask{Port: 0x00c8, Mask: 0x10}): via(5),
				PortMaskEncode(&PortMask{Port: 0x0078, Mask: 0x10}): via(6),
			},
			DstIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x6e0b0b18, Mask: 0x20}): via(0, 1, 2, 3, 4, 5, 6),
			},
			DstPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x16, Mask: 0x10}): via(0, 1, 2, 3, 4, 5, 6),
			},
			Action: map[string]IBitmap{
				ActionMaskEncode(&ActionMask{Action: 0x00, Mask: 0x08}): via(0, 1, 2, 3, 4, 5),
				ActionMaskEncode(&ActionMask{Action: 0x01, Mask: 0x08}): via(6),
			},
		},
	},
	"case-mulit-srcPort3": {
		rules: []*proto.FwRule{
			{
				Protocol: "udp",
				SrcIp:    "1.1.1.1/32",
				//	0x0064/14
				//	0x0068/13
				//	0x0070/12
				//	0x0080/10
				//	0x00c0/13
				//	0x00c8/16
				SrcPort: "100-200",
				DstIp:   "110.11.11.24/32",
				//	0x0064/14
				//	0x0068/15
				DstPort: "100-105",
				Action:  "drop",
			},
			{
				Protocol: "tcp",
				SrcIp:    "1.1.1.1/32",
				//	0x0078/16
				SrcPort: "120",
				DstIp:   "110.11.11.24/32",
				DstPort: "22",
				Action:  "accept",
			},
		},
		lbvs: &LBVS{
			Protocol: map[string]IBitmap{
				ProtoMaskEncode(&ProtoMask{Proto: number["udp"], Mask: 0x08}): via(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
				ProtoMaskEncode(&ProtoMask{Proto: number["tcp"], Mask: 0x08}): via(12),
			},
			SrcIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x01010101, Mask: 0x20}): via(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
			},
			SrcPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x0064, Mask: 0x0e}): via(0, 1),
				PortMaskEncode(&PortMask{Port: 0x0068, Mask: 0x0d}): via(2, 3),
				PortMaskEncode(&PortMask{Port: 0x0070, Mask: 0x0c}): via(4, 5, 12),
				PortMaskEncode(&PortMask{Port: 0x0080, Mask: 0x0a}): via(6, 7),
				PortMaskEncode(&PortMask{Port: 0x00c0, Mask: 0x0d}): via(8, 9),
				PortMaskEncode(&PortMask{Port: 0x00c8, Mask: 0x10}): via(10, 11),
				PortMaskEncode(&PortMask{Port: 0x0078, Mask: 0x10}): via(12),
			},
			DstIp: map[string]IBitmap{
				IpMaskEncode(&IpMask{Ip: 0x6e0b0b18, Mask: 0x20}): via(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
			},
			DstPort: map[string]IBitmap{
				PortMaskEncode(&PortMask{Port: 0x0064, Mask: 0x0e}): via(0, 2, 4, 6, 8, 10),
				PortMaskEncode(&PortMask{Port: 0x0068, Mask: 0x0f}): via(1, 3, 5, 7, 9, 11),
				PortMaskEncode(&PortMask{Port: 0x16, Mask: 0x10}):   via(12),
			},
			Action: map[string]IBitmap{
				ActionMaskEncode(&ActionMask{Action: 0x00, Mask: 0x08}): via(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
				ActionMaskEncode(&ActionMask{Action: 0x01, Mask: 0x08}): via(12),
			},
		},
	},
}

func Test_engine(t *testing.T) {
	var s = engine{bml: bml}
	for n, p := range testEngine {
		f := func(t *testing.T) {
			var act, err = s.parse(p.rules)
			if err != nil {
				t.Fatal(err)
				return
			}
			for i, v := range act {
				fmt.Printf("%d# %d %d %d %d %d %d %d %d %d %d\n", i, v.Protocol, v.SrcIp, v.SrcIpMask, v.SrcPort, v.SrcPortMask, v.DstIp, v.DstIpMask, v.DstPort, v.DstPortMask, v.Action)
			}
			var lbvs = s.analyze(act)
			equalMap(t, "proto", lbvs.Protocol, p.lbvs.Protocol)
			equalMap(t, "srcIp", lbvs.SrcIp, p.lbvs.SrcIp)
			equalMap(t, "srcPort", lbvs.SrcPort, p.lbvs.SrcPort)
			equalMap(t, "dstIp", lbvs.DstIp, p.lbvs.DstIp)
			equalMap(t, "dstPort", lbvs.DstPort, p.lbvs.DstPort)
			equalMap(t, "action", lbvs.Action, p.lbvs.Action)
		}
		t.Run(n, f)
	}
}

func equalMap(t *testing.T, name string, a map[string]IBitmap, b map[string]IBitmap) {
	if len(a) != len(b) {
		t.Fatalf("%s len(a) <> len(b)\n", name)
		return
	}
	for k, v := range a {
		vv, ok := b[k]
		if !ok {
			t.Fatalf("%s %s not in b\n", k, name)
			return
		}
		if !bytes.Equal(v.Bytes(), vv.Bytes()) {
			t.Fatalf("%s v != vv\n", name)
			return
		}
	}
}

func via(a ...int) IBitmap {
	var b = NewBitmap(bml)
	for _, i := range a {
		b.Set(uint16(i))
	}
	return b
}
