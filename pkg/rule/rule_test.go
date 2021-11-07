package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testPortMask = map[string]struct {
	min int
	max int
}{
	"case1": {
		min: 1,
		max: 65535,
	},
	"case2": {
		min: 22,
		max: 22,
	},
	"case3": {
		min: 3389,
		max: 4000,
	},
	"case4": {
		min: 2,
		max: 65534,
	},
	"case5": {
		min: 3306,
		max: 6379,
	},
}

func Test_portMask(t *testing.T) {
	for n, p := range testPortMask {
		f := func(t *testing.T) {
			var data, err = newPortMask(p.min, p.max)
			if err != nil {
				t.Fatal(err)
				return
			}
			//校验是否全覆盖
			var ok = false
			for i := p.min; i <= p.max; i++ {
				ok = false
				for _, v := range data {
					var mask = uint16(0xffff << (16 - uint16(v.Mask)))
					if uint16(i)&mask == v.Port {
						ok = true
						break
					} else {
						continue
					}
				}
				assert.Equal(t, ok, true)
			}
			//溢出校验
			var over = []uint16{uint16(p.min - 1), uint16(p.max + 1)}
			for _, i := range over {
				ok = false
				for _, v := range data {
					var mask = uint16(0xffff << (16 - uint16(v.Mask)))
					if i&mask == v.Port {
						ok = true
						break
					} else {
						continue
					}
				}
				assert.Equal(t, ok, false)
			}
		}
		t.Run(n, f)
	}
}

var testIpMask = map[string]struct {
	ip string
}{
	"case1": {
		ip: "192.168.1.1/24",
	},
	"case2": {
		ip: "192.168.1.2/0",
	},
	"case3": {
		ip: "0.0.0.0/32",
	},
}

func Test_ipMask(t *testing.T) {
	for n, p := range testIpMask {
		f := func(t *testing.T) {
			var a, err = newIpMask(p.ip)
			if err != nil {
				t.Fatal(err)
				return
			}
			t.Log(a)
		}
		t.Run(n, f)
	}
}
