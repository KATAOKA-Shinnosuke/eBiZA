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

BPF_HASH(dst_ts_hash, u32, u64);

int xdp_agent(struct __sk_buff *skb){
    void* data = (void *)(long)skb->data;
    void* data_end = (void *)(long)skb->data_end;

    struct ethhdr* eth = data;
    u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return TC_ACT_SHOT;

    u16 h_proto = eth->h_proto;
    if (h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = data + nh_off;
    
    if (data + nh_off + sizeof(struct iphdr) > data_end)
        return TC_ACT_SHOT;

    u64 *ts;
    ts = dst_ts_hash.lookup(&(iph->daddr));
    u64 now = bpf_ktime_get_ns();
    if(!ts){
        dst_ts_hash.insert(&(iph->daddr), &now);
    }
    else{
        if (now - *ts > 10000000000){
            dst_ts_hash.update(&(iph->daddr), &now);
        }
        else
            return TC_ACT_OK;
    }
    
    /*
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);;
    if (data + nh_off + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return TC_ACT_SHOT;*/

    if (iph->protocol == IPPROTO_UDP){
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        //struct udphdr udph = {};
        if (data + nh_off + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return TC_ACT_SHOT;


        udph->dest = htons(1024);
        udph->source = htons(0);
        return TC_ACT_OK;
        //udph.len = htons(sizeof(struct udphdr));

        //bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr),
        //                    &udph, sizeof(struct udphdr), 0);
        //bpf_clone_redirect(skb, skb->ifindex, 0);

        //bpf_busy_wait(1000000);

        //bpf_clone_redirect(skb, skb->ifindex, 0);

        //return TC_ACT_SHOT;
    }
    if (iph->protocol == IPPROTO_TCP){
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        //struct udphdr udph = {};
        if (data + nh_off + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
            return TC_ACT_SHOT;


        tcph->dest = htons(1024);
        tcph->source = htons(0);
        return TC_ACT_OK;
        //udph.len = htons(sizeof(struct udphdr));

        //bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr),
        //                    &tcph, sizeof(struct tcphdr), 0);
        //bpf_clone_redirect(skb, skb->ifindex, 0);

        //bpf_busy_wait(1000000);

        //bpf_clone_redirect(skb, skb->ifindex, 0);

        //return TC_ACT_SHOT;
    }

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