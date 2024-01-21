//#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>


BPF_HASH(allowed_src_hash, u32, u64);

int xdp_pep(struct xdp_md *ctx){
    void* data = (void *)(long)ctx->data;
    void* data_end = (void *)(long)ctx->data_end;

    struct ethhdr* eth = data;
    u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_ABORTED;

    u16 h_proto = eth->h_proto;
    if (h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + nh_off;
    
    if (data + nh_off + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    //認可要求パケットの内容チェック
    if(iph->protocol == IPPROTO_UDP){
        struct udphdr *udph = data + nh_off + sizeof(struct iphdr);
        if(data + nh_off + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return XDP_ABORTED;
        if (udph->dest == htons(1024)){
            if (ntohs(udph->source) < 50010) {
                u64 ts = bpf_ktime_get_ns();
                allowed_src_hash.insert(&(iph->saddr), &ts);
            }
            return XDP_DROP;
        }
    }
    if(iph->protocol == IPPROTO_TCP){
        struct tcphdr *tcph = data + nh_off + sizeof(struct iphdr);
        if(data + nh_off + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
            return XDP_ABORTED;
        if (tcph->dest == htons(1024)){
            if(ntohs(tcph->source) < 50010){
                u64 ts = bpf_ktime_get_ns();
                allowed_src_hash.insert(&(iph->saddr), &ts);
            }
            return XDP_DROP;
        }
    }


    u64* ts = allowed_src_hash.lookup(&(iph->saddr));

    if(!ts)
        return XDP_DROP;

    if(bpf_ktime_get_ns() - (*ts) >  30000000000){
        allowed_src_hash.delete(&(iph->saddr));
        return XDP_DROP;
    }

    return XDP_PASS;
}