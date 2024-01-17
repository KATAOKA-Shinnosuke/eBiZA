#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

BPF_HASH(allowed_src, u32, u64);

int xdp_nd(struct xdp_md *ctx){
    void* data = (void *)(long)ctx->data;
    void* data_end = (void *)(long)ctx->data_end;

    struct ethhdr* eth = data;
    u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_DROP;

    u16 h_proto = eth->h_proto;
    if (h_proto != htons(ETH_P_IP))
        return XDP_DROP;

    struct iphdr *iph = data + nh_off;
    
    if (data + nh_off + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if(is_spa_pkt(iph)){
        if(is_trustable(iph)){
            val = bpf_ktime_get_ns();
            allowed_src.insert(&iph->saddr, &val);
        }
    }
    else if(allowed_src.lookup(&iph->saddr)){
        return XDP_PASS;
    }

    return XDP_DROP;