#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//libpf 0.0.8 提交修改: https://lore.kernel.org/bpf/87lez87rbm.fsf@toke.dk/T/
struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key,          0x10);
   __type(value,        0x08);
   __uint(max_entries,  0x20);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} metadata SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key,          __KEY_SIZE__);
   __type(value,        __VAL_SIZE__);
   __uint(max_entries,  __MAX_ENTRY__);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_proto SEC(".maps"); 

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key,          __KEY_SIZE__);
   __type(value,        __VAL_SIZE__);
   __uint(max_entries,  __MAX_ENTRY__);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_action SEC(".maps"); 

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key,          __KEY_SIZE__);
   __type(value,        __VAL_SIZE__);
   __uint(max_entries,  __MAX_ENTRY__);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_nw_dst SEC(".maps"); 

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key,          __KEY_SIZE__);
   __type(value,        __VAL_SIZE__);
   __uint(max_entries,  __MAX_ENTRY__);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_nw_src SEC(".maps"); 

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key,          __KEY_SIZE__);
   __type(value,        __VAL_SIZE__);
   __uint(max_entries,  __MAX_ENTRY__);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_tp_dst SEC(".maps"); 

struct {
   __uint(type, BPF_MAP_TYPE_LPM_TRIE);
   __type(key,          __KEY_SIZE__);
   __type(value,        __VAL_SIZE__);
   __uint(max_entries,  __MAX_ENTRY__);
   __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_tp_src SEC(".maps"); 

static __inline void update_meta_info() {
    //bpf.tag
    //格式: x.y.z [x=2B y=2B z=4B]
    char    name[0x10];
    char    value[0x08];
    __be64  tag     = __TAG__;
    __be64  commit  = __COMMIT__;
    __be64  ksize   = __KEY_SIZE__;
    __be64  vsize   = __VAL_SIZE__;
    
    name[0x00] = 'b';
    name[0x01] = 'p';
    name[0x02] = 'f';
    name[0x03] = '.';
    name[0x04] = 't';
    name[0x05] = 'a';
    name[0x06] = 'g';
    name[0x07] = 0x00;
    name[0x08] = 0x00;
    name[0x09] = 0x00;
    name[0x0a] = 0x00;
    name[0x0b] = 0x00;
    name[0x0c] = 0x00;
    name[0x0d] = 0x00;
    name[0x0e] = 0x00;
    name[0x0f] = 0x00;

    value[0x00] = (unsigned char)(tag >> 56);
    value[0x01] = (unsigned char)(tag >> 48);
    value[0x02] = (unsigned char)(tag >> 40);
    value[0x03] = (unsigned char)(tag >> 32);
    value[0x04] = (unsigned char)(tag >> 24);
    value[0x05] = (unsigned char)(tag >> 16);
    value[0x06] = (unsigned char)(tag >> 8);
    value[0x07] = (unsigned char)(tag);
    bpf_map_update_elem(&metadata, name, value, BPF_ANY);

    name[0x00] = 'b';
    name[0x01] = 'p';
    name[0x02] = 'f';
    name[0x03] = '.';
    name[0x04] = 'c';
    name[0x05] = 'o';
    name[0x06] = 'm';
    name[0x07] = 'm';
    name[0x08] = 'i';
    name[0x09] = 't';
    name[0x0a] = 0x00;
    name[0x0b] = 0x00;
    name[0x0c] = 0x00;
    name[0x0d] = 0x00;
    name[0x0e] = 0x00;
    name[0x0f] = 0x00;

    value[0x00] = (unsigned char)(commit >> 56);
    value[0x01] = (unsigned char)(commit >> 48);
    value[0x02] = (unsigned char)(commit >> 40);
    value[0x03] = (unsigned char)(commit >> 32);
    value[0x04] = (unsigned char)(commit >> 24);
    value[0x05] = (unsigned char)(commit >> 16);
    value[0x06] = (unsigned char)(commit >> 8);
    value[0x07] = (unsigned char)(commit);
    bpf_map_update_elem(&metadata, name, value, BPF_ANY);

    name[0x00] = 'b';
    name[0x01] = 'p';
    name[0x02] = 'f';
    name[0x03] = '.';
    name[0x04] = 'l';
    name[0x05] = 'p';
    name[0x06] = 'm';
    name[0x07] = 'k';
    name[0x08] = 'e';
    name[0x09] = 'y';
    name[0x0a] = 0x00;
    name[0x0b] = 0x00;
    name[0x0c] = 0x00;
    name[0x0d] = 0x00;
    name[0x0e] = 0x00;
    name[0x0f] = 0x00;

    value[0x00] = (unsigned char)(ksize >> 56);
    value[0x01] = (unsigned char)(ksize >> 48);
    value[0x02] = (unsigned char)(ksize >> 40);
    value[0x03] = (unsigned char)(ksize >> 32);
    value[0x04] = (unsigned char)(ksize >> 24);
    value[0x05] = (unsigned char)(ksize >> 16);
    value[0x06] = (unsigned char)(ksize >> 8);
    value[0x07] = (unsigned char)(ksize);
    bpf_map_update_elem(&metadata, name, value, BPF_ANY);

    name[0x00] = 'b';
    name[0x01] = 'p';
    name[0x02] = 'f';
    name[0x03] = '.';
    name[0x04] = 'l';
    name[0x05] = 'p';
    name[0x06] = 'm';
    name[0x07] = 'v';
    name[0x08] = 'a';
    name[0x09] = 'l';
    name[0x0a] = 0x00;
    name[0x0b] = 0x00;
    name[0x0c] = 0x00;
    name[0x0d] = 0x00;
    name[0x0e] = 0x00;
    name[0x0f] = 0x00;

    value[0x00] = (unsigned char)(vsize >> 56);
    value[0x01] = (unsigned char)(vsize >> 48);
    value[0x02] = (unsigned char)(vsize >> 40);
    value[0x03] = (unsigned char)(vsize >> 32);
    value[0x04] = (unsigned char)(vsize >> 24);
    value[0x05] = (unsigned char)(vsize >> 16);
    value[0x06] = (unsigned char)(vsize >> 8);
    value[0x07] = (unsigned char)(vsize);
    bpf_map_update_elem(&metadata, name, value, BPF_ANY);
}

static __inline unsigned char *query_meta_fw_zone() {
    update_meta_info();

    char name[0x10];
    name[0x00] = 'f';
    name[0x01] = 'w';
    name[0x02] = '.';
    name[0x03] = 'z';
    name[0x04] = 'o';
    name[0x05] = 'n';
    name[0x06] = 'e';
    name[0x07] = 0x00;
    name[0x08] = 0x00;
    name[0x09] = 0x00;
    name[0x0a] = 0x00;
    name[0x0b] = 0x00;
    name[0x0c] = 0x00;
    name[0x0d] = 0x00;
    name[0x0e] = 0x00;
    name[0x0f] = 0x00;
    unsigned char *zone = (unsigned char*)bpf_map_lookup_elem(&metadata, name);
    return zone;
}

static __inline unsigned char* query_fw_proto_bits(unsigned char *zone, __u8 proto) {
    unsigned char kk[__KEY_SIZE__];
    kk[0x00] = 0x60;
    kk[0x01] = 0x00;
    kk[0x02] = 0x00;
    kk[0x03] = 0x00;
    kk[0x04] = zone[0x00];
    kk[0x05] = zone[0x01]; 
    kk[0x06] = zone[0x02]; 
    kk[0x07] = zone[0x03]; 
    kk[0x08] = zone[0x04]; 
    kk[0x09] = zone[0x05]; 
    kk[0x0a] = zone[0x06]; 
    kk[0x0b] = zone[0x07]; 
    kk[0x0c] = 0x00;
    kk[0x0d] = 0x00;
    kk[0x0e] = 0x00;
    kk[0x0f] = proto;
    
    unsigned char *bits = (unsigned char*)bpf_map_lookup_elem(&ipv4_proto, kk);
    return bits;
}

static __inline unsigned char* query_fw_nw_src_bits(unsigned char *zone, __be32 src_ip) {
    unsigned char kk[__KEY_SIZE__];
    kk[0x00] = 0x60;
    kk[0x01] = 0x00;
    kk[0x02] = 0x00;
    kk[0x03] = 0x00;
    kk[0x04] = zone[0x00];
    kk[0x05] = zone[0x01]; 
    kk[0x06] = zone[0x02]; 
    kk[0x07] = zone[0x03]; 
    kk[0x08] = zone[0x04]; 
    kk[0x09] = zone[0x05]; 
    kk[0x0a] = zone[0x06]; 
    kk[0x0b] = zone[0x07]; 
    kk[0x0c] = (unsigned char)(src_ip);
    kk[0x0d] = (unsigned char)(src_ip >> 8);
    kk[0x0e] = (unsigned char)(src_ip >> 16);
    kk[0x0f] = (unsigned char)(src_ip >> 24);
    
    unsigned char *bits = (unsigned char*)bpf_map_lookup_elem(&ipv4_nw_src, kk);
    return bits;
}

static __inline unsigned char* query_fw_nw_dst_bits(unsigned char *zone, __be32 dst_ip) {
    unsigned char kk[__KEY_SIZE__];
    kk[0x00] = 0x60;
    kk[0x01] = 0x00;
    kk[0x02] = 0x00;
    kk[0x03] = 0x00;
    kk[0x04] = zone[0x00];
    kk[0x05] = zone[0x01]; 
    kk[0x06] = zone[0x02]; 
    kk[0x07] = zone[0x03]; 
    kk[0x08] = zone[0x04]; 
    kk[0x09] = zone[0x05]; 
    kk[0x0a] = zone[0x06]; 
    kk[0x0b] = zone[0x07]; 
    kk[0x0c] = (unsigned char)(dst_ip);
    kk[0x0d] = (unsigned char)(dst_ip >> 8);
    kk[0x0e] = (unsigned char)(dst_ip >> 16);
    kk[0x0f] = (unsigned char)(dst_ip >> 24);
    
    unsigned char *bits = (unsigned char*)bpf_map_lookup_elem(&ipv4_nw_dst, kk);
    return bits;
}

static __inline unsigned char* query_fw_tp_src_bits(unsigned char *zone, __be16 src_port) {
    unsigned char kk[__KEY_SIZE__];
    kk[0x00] = 0x60;
    kk[0x01] = 0x00;
    kk[0x02] = 0x00;
    kk[0x03] = 0x00;
    kk[0x04] = zone[0x00];
    kk[0x05] = zone[0x01]; 
    kk[0x06] = zone[0x02]; 
    kk[0x07] = zone[0x03]; 
    kk[0x08] = zone[0x04]; 
    kk[0x09] = zone[0x05]; 
    kk[0x0a] = zone[0x06]; 
    kk[0x0b] = zone[0x07]; 
    kk[0x0c] = 0x00;
    kk[0x0d] = 0x00;
    kk[0x0e] = (unsigned char)(src_port);
    kk[0x0f] = (unsigned char)(src_port >> 8);
    
    unsigned char *bits = (unsigned char*)bpf_map_lookup_elem(&ipv4_tp_src, kk);
    return bits;
}

static __inline unsigned char* query_fw_tp_dst_bits(unsigned char *zone, __be16 dst_port) {
    unsigned char kk[__KEY_SIZE__];
    kk[0x00] = 0x60;
    kk[0x01] = 0x00;
    kk[0x02] = 0x00;
    kk[0x03] = 0x00;
    kk[0x04] = zone[0x00];
    kk[0x05] = zone[0x01]; 
    kk[0x06] = zone[0x02]; 
    kk[0x07] = zone[0x03]; 
    kk[0x08] = zone[0x04]; 
    kk[0x09] = zone[0x05]; 
    kk[0x0a] = zone[0x06]; 
    kk[0x0b] = zone[0x07]; 
    kk[0x0c] = 0x00;
    kk[0x0d] = 0x00;
    kk[0x0e] = (unsigned char)(dst_port);
    kk[0x0f] = (unsigned char)(dst_port >> 8);
    
    unsigned char *bits = (unsigned char*)bpf_map_lookup_elem(&ipv4_tp_dst, kk);
    return bits;
}

static __inline unsigned char* query_fw_action_bits(unsigned char *zone, __u8 op) {
    unsigned char kk[__KEY_SIZE__];
    kk[0x00] = 0x60;
    kk[0x01] = 0x00;
    kk[0x02] = 0x00;
    kk[0x03] = 0x00;
    kk[0x04] = zone[0x00];
    kk[0x05] = zone[0x01]; 
    kk[0x06] = zone[0x02]; 
    kk[0x07] = zone[0x03]; 
    kk[0x08] = zone[0x04]; 
    kk[0x09] = zone[0x05]; 
    kk[0x0a] = zone[0x06]; 
    kk[0x0b] = zone[0x07]; 
    kk[0x0c] = 0x00;
    kk[0x0d] = 0x00;
    kk[0x0e] = 0x00;
    kk[0x0f] = op;
    
    unsigned char *bits = (unsigned char*)bpf_map_lookup_elem(&ipv4_action, kk);
    return bits;
}

static __inline int security_strategy(__u8 proto, __be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port) {
    int rc = XDP_DROP;  //默认拒绝

    unsigned char *zone = query_meta_fw_zone();
    if (!zone) {
        goto leave;
    }
    unsigned char *proto_bits = query_fw_proto_bits(zone, proto);
    if (!proto_bits) {
        goto leave;
    }
    //#bpf_printk("bits=%x proto=%x\n", *proto_bits, proto); 
    unsigned char *nw_src_bits = query_fw_nw_src_bits(zone, src_ip); 
    if (!nw_src_bits) {
        goto leave;
    }
    //#bpf_printk("bits=%x nw_src=%x\n", *nw_src_bits, src_ip); 
    unsigned char *nw_dst_bits = query_fw_nw_dst_bits(zone, dst_ip);
    if (!nw_dst_bits) {
        goto leave;
    }
    //#bpf_printk("bits=%x nw_dst=%x\n", *nw_dst_bits, dst_ip); 
    unsigned char *tp_src_bits = query_fw_tp_src_bits(zone, src_port);
    if (!tp_src_bits) {
        goto leave;
    }
    //#bpf_printk("bits=%x tp_src=%x\n", *tp_src_bits, src_port); 
    unsigned char *tp_dst_bits = query_fw_tp_dst_bits(zone, dst_port);
    if (!tp_dst_bits) {
        goto leave;
    }
    //#bpf_printk("bits=%x tp_dst=%x\n", *tp_dst_bits, dst_port); 
    unsigned char *accept = query_fw_action_bits(zone, 0x01);
    if (!accept) {
        goto leave;
    }
    //#bpf_printk("bits=%x op=%x\n", *accept, 0x01); 
    unsigned char r[__VAL_SIZE__];
    int  i = 0;
    for (i = 0; i < __VAL_SIZE__; i++) {
        r[i] =  proto_bits[i] & nw_src_bits[i] & nw_dst_bits[i] & tp_src_bits[i] & tp_dst_bits[i] & accept[i];
        if (r[i] > 0x00) {
            rc = XDP_PASS;
            break;
        }
    }

leave:
    return rc;
}


SEC("xdp_fw")
int xpd_handle_fw(struct xdp_md *ctx) {
    //1. 定义变量
    int rc = XDP_DROP;  //默认拒绝

    void *data = (void*)(ctx->data);
    void *data_end = (void*)(ctx->data_end);

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
