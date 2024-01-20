//#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


struct key_addr_pair {
    u32 src_addr;
    u32 dst_addr;
};

struct key_new_addr {
    u64 src_addr;
    u64 timestamp;
};

BPF_HASH(prev_access_hash, struct key_addr_pair, u64, 40960); //store previous access - sec-addr dst-addr pair
BPF_QUEUE(new_access_queue, struct key_new_addr, 10240); //hold new access -- src_addr time pair
BPF_HASH(count_hash, u32, u32); // count scan per src-addr;

//BPF_QUEUE(test_queue, u32, 10240);
//BPF_HASH(test_hash, u32, u32);

/*
static inline int parse_ipv4(void* data, u64 nh_off, void* data_end){
    struct iphdr* iph = data + nh_off;

    if((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void* data, u64 nh_off, void* data_end){
    struct ipv6hdr *ip6h = data + nh_off;

    if((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}
*/

int xdp_nd(struct xdp_md *ctx){
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

    
    struct key_addr_pair addr_pair = { (iph->saddr), (iph->daddr) };
    
    if(!(prev_access_hash.lookup(&addr_pair))) { // new src-dst pair
        u64 v64 = 1;
        u32 v32 = 1;
        prev_access_hash.insert(&addr_pair, &v64);
        
        if(!count_hash.lookup(&(iph->saddr)))
            count_hash.insert(&(iph->saddr), &v32);
        else
            count_hash.increment(iph->saddr);

        struct key_new_addr new_addr = {(u64)(iph->saddr), bpf_ktime_get_ns()};
        new_access_queue.push(&new_addr, BPF_EXIST);
        //bpf_map_push_elem(&new_access_queue, &new_addr, BPF_EXIST);
    }
    else{
        prev_access_hash.increment(addr_pair);
    }
    
    u64 time = bpf_ktime_get_ns();
    //u32 val = 123456789;
    //test_queue.push(&val, BPF_EXIST);
    //bpf_map_update_elem(&test_queue, &val, BPF_EXIST);
    
    struct key_new_addr old_access = {0,0};
    for(int i=0; i<2048; i++){
        if(new_access_queue.peek(&old_access) == 0 &&
           bpf_ktime_get_ns() - (old_access.timestamp) > 50000000000){
                new_access_queue.pop(&old_access);
                count_hash.increment((iph->saddr), -1);
           }
        else
            break;
    }
    

    return XDP_PASS;

    /*if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)){
        struct vlan_hdr* vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
            h_proto = 
    }*/

    /*
    u32 index;

    if (h_proto == htons(ETH_P_IP))
        index = parse_ipv4(data, nh_off, data_end);
    else if(h_proto == htons(ETH_P_IPV6))
        index = parse_ipv6(data, nh_off, data_end);
    else
        index = 0;

    if(is_spa_pkt(iph)) {
        add_network_info(iph);
        return XDP_TX;
    }
    else{
        return XDP_PASS;
    }*/
}

/*int xdp_drop_icmp(struct xdp_md *ctx) {
    void* data_end = (void *)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;
    u64 nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_PASS;

    if (eth->h_proto == htons(ETH_P_IP)) {
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
    }

    return XDP_PASS;
}*/
