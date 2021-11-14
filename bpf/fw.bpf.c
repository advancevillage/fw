#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

//定义数据Map和用户态通讯. 在内核态定义的map需要被引用. 如果未引用在加载过程中会被优化删除
//map name:         iptables
//map key_size:     0x10
//map value_size:   0x20
//map max_entries:  0x10
//map flags:        0x0
struct bpf_map_def SEC("maps") iptables = {
	.type    	 = BPF_MAP_TYPE_HASH,
    .key_size	 = 0x10,
    .value_size	 = 0x20,
    .max_entries = 0x10,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

SEC("xdp_fw")
int xpd_handle_fw(struct xdp_md *ctx) {
    int rc = XDP_PASS;
        return rc;
}

char _license []SEC("license") = "GPL";


//clang -g -Wall -O2 -c -target bpf -D__TARGET_ARCH_x86 fw.bpf.c -I/usr/include/x86_64-linux-gnu/ -o fw.bpf.o 
