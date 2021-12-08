#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define keySize     0x10
#define valueSize   0x04
#define maxEntry    (0x01 << 16) 

//定义元数据
//map name:         metadata
//map key_size:     0x10
//map value_size:   0x08
//map max_entries:  0x20
struct bpf_map_def SEC("maps") metadata = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size	 = 0x10,
    .value_size	 = 0x08,
    .max_entries = 0x20,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ipv4_proto = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size	 = keySize,
    .value_size	 = valueSize,
    .max_entries = maxEntry,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ipv4_action = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size	 = keySize,
    .value_size	 = valueSize,
    .max_entries = maxEntry,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ipv4_nw_dst = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size	 = keySize,
    .value_size	 = valueSize,
    .max_entries = maxEntry,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ipv4_nw_src = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size	 = keySize,
    .value_size	 = valueSize,
    .max_entries = maxEntry,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ipv4_tp_dst = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size	 = keySize,
    .value_size	 = valueSize,
    .max_entries = maxEntry,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") ipv4_tp_src = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size	 = keySize,
    .value_size	 = valueSize,
    .max_entries = maxEntry,
    .map_flags	 = BPF_F_NO_PREALLOC,
};

static __inline unsigned char *query_meta_fw_zone() {
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
    if (!zone) {
        return NULL;
    }
    return zone;
}

static __inline unsigned char* query_fw_proto_bits(unsigned char *zone, __u8 proto) {
    unsigned char kk[keySize];
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
    if (!bits) {
        return NULL;
    }
    return bits;
}

static __inline unsigned char* query_fw_nw_src_bits(unsigned char *zone, __be32 src_ip) {
    unsigned char kk[keySize];
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
    if (!bits) {
        return NULL;
    }
    return bits;
}

static __inline unsigned char* query_fw_nw_dst_bits(unsigned char *zone, __be32 dst_ip) {
    unsigned char kk[keySize];
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
    if (!bits) {
        return NULL;
    }
    return bits;
}

static __inline unsigned char* query_fw_tp_src_bits(unsigned char *zone, __be16 src_port) {
    unsigned char kk[keySize];
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
    if (!bits) {
        return NULL;
    }
    return bits;
}

static __inline unsigned char* query_fw_tp_dst_bits(unsigned char *zone, __be16 dst_port) {
    unsigned char kk[keySize];
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
    if (!bits) {
        return NULL;
    }
    return bits;
}

static __inline unsigned char* query_fw_action_bits(unsigned char *zone, __u8 op) {
    unsigned char kk[keySize];
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
    if (!bits) {
        return NULL;
    }
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
    unsigned char *nw_src_bits = query_fw_nw_src_bits(zone, src_ip); 
    if (!nw_src_bits) {
        goto leave;
    }
    unsigned char *nw_dst_bits = query_fw_nw_dst_bits(zone, dst_ip);
    if (!nw_dst_bits) {
        goto leave;
    }
    unsigned char *tp_src_bits = query_fw_tp_src_bits(zone, src_port);
    if (!tp_src_bits) {
        goto leave;
    }
    unsigned char *tp_dst_bits = query_fw_tp_dst_bits(zone, dst_port);
    if (!tp_dst_bits) {
        goto leave;
    }
    unsigned char *accept = query_fw_action_bits(zone, 0x01);
    if (!accept) {
        goto leave;
    }

    char r[valueSize];
    int  i = 0;
    for (i = 0; i < valueSize; i++) {
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
