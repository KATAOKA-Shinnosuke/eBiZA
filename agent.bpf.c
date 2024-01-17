#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


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

    u32 protocol;
    protocol = iph->protocol;

    if (protocol != 6)
        return XDP_PASS;

    generate_spa_pkt(iph);
    return XDP_TX;

    /*if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr* iph = data + nh_off;
        if ((void*)&iph[1] > data_end)
            return XDP_PASS;
        u32 protocol;
        protocol = iph->protocol;
        if (protocol == 1) {
            u32 value = 0, *vp;
            vp = dropncnt.lookup_or_init(&protocol, &value);
            *vp += 1;
            return XDP_DROP;
        }
    }*/
}