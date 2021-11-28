#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


//定义数据Map和用户态通讯. 在内核态定义的map需要被引用. 如果未引用在加载过程中会被优化删除
//map name:         iptables
//map key_size:     0x10
//map value_size:   0x20
//map max_entries:  0x10
//map flags:        0x0
struct bpf_map_def SEC("maps") iptables = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size	 = 0x10,
    .value_size	 = 0x20,
    .max_entries = 0x10,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

static __inline unsigned char *query_security_value() {
    unsigned char  security_ptr[0x10] = {'s', 'e', 'c', 'u', 'r', 'i', 't', 'y', '.', 'p', 't', 'r', 0, 0, 0, 0};
    unsigned char  *security_value = NULL;
    
    security_value = bpf_map_lookup_elem(&iptables, security_ptr);

    return security_value;
}

static __inline int security_strategy(__u8 proto, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port) {
    int rc = XDP_DROP;  //默认拒绝

    //获取iptables 防火墙表
    unsigned char *name_and_ver = query_security_value();
    if (!name_and_ver) {
        return rc;
    }
    //调试 https://github.com/libbpf/libbpf/blob/master/src/bpf_helpers.h 
    //注意: bpf_printk args 最多3个
    bpf_printk("name_and_ver = %s\n", (char*)name_and_ver); 
    bpf_printk("srcIp=%x srcPort=%x proto=%x\n",src_ip, src_port, proto); 
    bpf_printk("dstIp=%x dstPort=%x proto=%x\n",dst_ip, dst_port, proto); 
    //TODO: 动态加载策略表通过表名


    rc = XDP_PASS;
    return rc;
}


SEC("xdp_iptables")
int xpd_handle_iptables(struct xdp_md *ctx) {
    //1. 定义变量
    int rc = XDP_DROP;  //默认拒绝

    void *data = (void *)ctx->data;
    void *data_end = (void *)ctx->data_end;

    //2. 解析以太网协议头
    struct ethhdr *eth = data;
    __be64 nh_off;
    __be16 h_proto;

    nh_off = (char*)(eth + 1) - (char*)eth;
    if (data + nh_off > data_end) {
        goto end;
    }
    //https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h
    h_proto = eth->h_proto;

    //https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/if_ether.h#L54
    switch (h_proto) {
    case bpf_htons(ETH_P_ARP):
        rc = XDP_PASS;
        goto end;
    case bpf_htons(ETH_P_RARP):
        rc = XDP_PASS;
        goto end;
    case bpf_htons(ETH_P_8021Q):
        //https://elixir.bootlin.com/linux/latest/source/include/linux/if_vlan.h
        goto end;
    case bpf_htons(ETH_P_8021AD):
        goto end;
    case bpf_htons(ETH_P_IP):
        break;
    case bpf_htons(ETH_P_IPV6):
        goto end;
    default:
        goto end;
    }

    //解析网络层协议
    struct iphdr *iph = data + nh_off;
    nh_off += (char*)(iph + 1) - (char*)iph;
    if (data + nh_off > data_end) {
        goto end;
    }
    //不支持分片报文
    // 001 0 0000 0000 0000
    if (iph->frag_off & 0x2000) {
        goto end;
    }

    __u8    proto       = 0;
    __be32  src_ip      = 0;
    __be32  dst_ip      = 0;
    __be16  src_port    = 0;
    __be16  dst_port    = 0;

    //https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    proto   = iph->protocol;
    src_ip  = iph->saddr;
    dst_ip  = iph->daddr;
    switch(proto) {
    case 0x01: //icmp
        break;
    case 0x06: //tcp
        {
            struct tcphdr *tcph = data + nh_off;
            nh_off += (char*)(tcph + 1) - (char*)tcph;
            if (data + nh_off > data_end) {
                goto end;
            }
            src_port = tcph->source;
            dst_port = tcph->dest;
        }
        break;
    case 0x11: //udp
        {
            struct udphdr *udph = data + nh_off;
            nh_off += (char*)(udph + 1) - (char*)udph;
            if (data + nh_off > data_end) {
                goto end;
            }
            src_port = udph->source;
            dst_port = udph->dest;
        }
        break;
    case 0x2f: //gre
        break;
    default:
        goto end;
    }

    rc = security_strategy(proto, src_ip, src_port, dst_ip, dst_port);

end:
    return rc;
}

char _license []SEC("license") = "GPL";


//clang -g -Wall -O2 -c -target bpf -D__TARGET_ARCH_x86 fw.bpf.c -I/usr/include/x86_64-linux-gnu/ -o fw.bpf.o 
