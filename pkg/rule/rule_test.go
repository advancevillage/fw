package rule

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().Unix())
}

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
	"case6": {
		min: 1100,
		max: 1200,
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
	ip  string
	exp *IpMask
}{
	"case1": {
		ip: "192.168.1.1/24",
		exp: &IpMask{
			Ip:   0xc0a80100,
			Mask: 24,
		},
	},
	"case2": {
		ip: "192.168.1.2/0",
		exp: &IpMask{
			Ip:   0,
			Mask: 0,
		},
	},
	"case3": {
		ip: "0.0.0.0/32",
		exp: &IpMask{
			Ip:   0,
			Mask: 32,
		},
	},
	"case4": {
		ip: "192.168.1.1",
		exp: &IpMask{
			Ip:   0xc0a80101,
			Mask: 32,
		},
	},
	"case5": {
		ip: "0.0.0.0",
		exp: &IpMask{
			Ip:   0,
			Mask: 32,
		},
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
			assert.Equal(t, a, p.exp)
		}
		t.Run(n, f)
	}
}

var testBitmap = map[string]struct {
	start uint16
	end   uint16
}{
	"case1": {
		start: uint16(rand.Intn(100)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case2": {
		start: uint16(rand.Intn(200)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case3": {
		start: uint16(rand.Intn(300)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case4": {
		start: uint16(rand.Intn(400)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case5": {
		start: uint16(rand.Intn(500)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case6": {
		start: uint16(rand.Intn(600)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case7": {
		start: uint16(rand.Intn(700)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case8": {
		start: uint16(rand.Intn(800)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case9": {
		start: uint16(rand.Intn(900)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case10": {
		start: uint16(rand.Intn(1000)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case11": {
		start: uint16(rand.Intn(1100)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case12": {
		start: uint16(rand.Intn(10)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case13": {
		start: uint16(rand.Intn(20)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case14": {
		start: uint16(rand.Intn(30)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case15": {
		start: uint16(rand.Intn(40)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case16": {
		start: uint16(rand.Intn(50)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case17": {
		start: uint16(rand.Intn(60)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case18": {
		start: uint16(rand.Intn(70)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case19": {
		start: uint16(rand.Intn(80)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
	"case20": {
		start: uint16(rand.Intn(90)),
		end:   uint16(rand.Intn(1024) + 1024),
	},
}

func Test_bitmap(t *testing.T) {
	var bm = NewBitmap(BitmapLength)
	var ety = NewBitmap(BitmapLength)
	for n, p := range testBitmap {
		f := func(t *testing.T) {
			for i := p.start; i < p.end; i++ {
				bm.Set(i)
			}
			for i := p.start; i < p.end; i++ {
				bm.Unset(i)
			}
			assert.Equal(t, bm, ety)
		}
		t.Run(n, f)
	}

}
