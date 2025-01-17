#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#define server_prefix 0x0A01u
struct udppayload
{
    unsigned short data;
};

struct wlist
{
    unsigned char data[32];
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, int);
    __type(value, struct wlist);
} dest_limiter_array SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
    {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_UDP)
    {
        // Parse UDP header
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        if (__builtin_bswap16(udph->dest) >= 1000 && __builtin_bswap16(udph->dest) <= 2000 && (__builtin_bswap32(iph->daddr) >> 16) == server_prefix)
        {
            if (__builtin_bswap16(udph->len) == 10)
            {
                struct udppayload* payload = (struct udppayload *)(udph + 1);
                if ((void *)(payload + 1) > data_end)
                    return XDP_DROP;
                if (udph->dest == payload->data) {
                    int key = __builtin_bswap32(iph->saddr) >> 16;
                    int bitp = (__builtin_bswap32(iph->saddr) >> 8) & 0xffu;
                    struct wlist* w = bpf_map_lookup_elem(&dest_limiter_array, &key);
                    if (!w)
                    {
                        // bpf_printk("map not found");
                        return XDP_DROP;
                    }

                    w->data[bitp / 8] |= 1 << (bitp % 8);

                    // bpf_printk("add %u to whitelist port %u index %u array %u bit %u",__builtin_bswap32(iph->saddr) & 0xffffff00u, __builtin_bswap16(payload->data), key, bitp/8, 1 << (bitp % 8));
                    return XDP_DROP;
                }
            }

            // bpf_printk("drop packet from %u port %u", __builtin_bswap32(iph->saddr), __builtin_bswap16(udph->dest));
            return XDP_DROP;
        }

        return XDP_PASS;
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            return XDP_DROP;
        if (tcph->syn && tcph->ack == 0 && __builtin_bswap16(tcph->dest) == 443 && (__builtin_bswap32(iph->daddr) >> 16) == server_prefix)
        {
            int key = __builtin_bswap32(iph->saddr) >> 16;
            int bitp = (__builtin_bswap32(iph->saddr) >> 8) & 0xffu;
            struct wlist* w = bpf_map_lookup_elem(&dest_limiter_array, &key);
            if (!w)
            {
                // bpf_printk("map not found");
                return XDP_PASS;
            }

            if (w->data[bitp / 8] &  (1 << (bitp % 8)))
            {
                // pf_printk("whitelist match");
                return XDP_PASS;
            }
            else return XDP_DROP;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
