from bcc import BPF
from pyroute2 import IPRoute
import pyroute2

from kube_query import *

bpf_program = """
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <linux/udp.h>
#include <linux/tcp.h> // --> struct tcphdr tcp;


#define SRC_IP 0x0A000194  // 10.0.1.148 (hex representation)
#define SVCIP 0x0A696F5D // 10.105.111.93 (hex representation)
#define NEW_DST_IP 0x0A000132  // 10.0.1.50 (hex representation)
#define NEW_DST_IP2 0x0A00012A  // 10.0.1.42

#define IS_PSEUDO 0x10
#define FLOW_TIMEOUT_NS (120ULL * 1000 * 1000 * 1000)

struct ct_key {
    u32 src_ip;
    u16 src_port;
    u8  proto;
};

struct ct_val {
    u32 backend_ip;
    u16 backend_port;
    u16 rev_nat_index;
};

struct rev_nat_val {
    u32 client_ip;
    u16 client_port;
};

BPF_TABLE("lru_hash", struct ct_key, struct ct_val, ct_map, 65536);
BPF_TABLE("lru_hash", u16, struct rev_nat_val, rev_nat_map, 65536);

BPF_HASH(backend_set, u32, u8);

static inline int parse_l4(struct __sk_buff *skb, struct iphdr *ip, u16 *src_port) {
    u8 proto = ip->protocol;
    int l4_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

    if (proto == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
            return -1;
        *src_port = tcp.source;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
            return -1;
        *src_port = udp.source;
    } else {
        return -1;
    }
    return 0;
}

int redirect_service(struct __sk_buff *skb) {
    int ifindex = skb->ifindex;
    bpf_trace_printk("redirect_service tc_ingress on ifindex=%d\\n", ifindex);

   
   void *data = (void *)(long)skb->data; 
   void *data_end = (void *)(long)skb->data_end; 
   struct ethhdr *eth = data; 
    if ((void *)(eth + 1) > data_end) 
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) 
        return TC_ACT_OK;
    struct iphdr *ip = data + sizeof(struct ethhdr); 
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK; 
    if (ip->ihl < 5) { 
        bpf_trace_printk("Invalid IP header length: %d\\n", ip->ihl); 
        return TC_ACT_SHOT; 
    }
   u32 old_dstip = ip->daddr;
   u32 old_srcip = ip->saddr;
   u8 ip_hl = ip->ihl; // To suppress unused variable warning
   u32 dst_ip = bpf_ntohl(ip->daddr);
   u32 src_ip = bpf_ntohl(ip->saddr);     
   
    // Check reply first
   struct ct_key key = { .src_ip = 0, .src_port = 0, .proto = 0};
   key.src_ip = dst_ip;
   key.proto = ip->protocol;
   int l4_offset = sizeof(struct ethhdr) + (ip->ihl * 4);
   
   if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
        return TC_ACT_SHOT;
    key.src_port = tcp.dest;
   }

   u8 *is_backend = backend_set.lookup(&src_ip);
   int ip_offset = 14;
   struct ct_val *ct = ct_map.lookup(&key);
   if (ct) {
        bpf_trace_printk("Found CT entry for reply packet\\n");
        u16 rev = ct->rev_nat_index;
        struct rev_nat_val *rev_val = rev_nat_map.lookup(&rev);
        if (rev_val) {
            u32 new_src_ip = bpf_ntohl(rev_val->client_ip); // From pod IP to svc IP
            // Store the updated destination IP in the packet   
            if (bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, saddr), &new_src_ip, sizeof(new_src_ip), 0) < 0) {
                bpf_trace_printk("Failed to modify saddr\\n");
                bpf_trace_printk("bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, saddr), &new_src_ip, sizeof(new_src_ip), 0) < 0\\n");   
                return TC_ACT_SHOT;
            }
            
            if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), old_srcip, new_src_ip, sizeof(new_src_ip)) < 0) {
                bpf_trace_printk("Failed to update IP l3 checksum\\n");
                return TC_ACT_SHOT;
            }
            
            u16 protocol = key.proto;
            if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {

                // Determine checksum offset based on protocol
                int csum_offset = (protocol == IPPROTO_TCP) ? 16 : 6;
                // int flags = (protocol == IPPROTO_UDP) ? BPF_F_PSEUDO_HDR : 0;  // UDP needs pseudo-header
                int flags = (protocol == IPPROTO_UDP) ? (BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0) : 0;

                // Check packet length
                if (skb->len < l4_offset + csum_offset + 2) {
                    bpf_trace_printk("Packet too short for L4 checksum update\\n");
                    return TC_ACT_SHOT;
                }
                if (bpf_skb_pull_data(skb, l4_offset + csum_offset + 2) < 0) {
                    bpf_trace_printk("Failed to pull skb data\\n");
                    return TC_ACT_SHOT;
                }
                // Update the L4 checksum
                flags = flags | 4;
                int ret = bpf_l4_csum_replace(skb, l4_offset + csum_offset, old_srcip, new_src_ip, IS_PSEUDO | flags);
                if (ret < 0) {
                    bpf_trace_printk("Failed to update L4 checksum %d\\n", ret);
                    return TC_ACT_SHOT;
                }
            }
            return TC_ACT_OK;
        }
   }
   
    if (dst_ip == SVCIP) {
        bpf_trace_printk("Service IP matched, processing packet\\n");
        struct ct_key key = { .src_ip = 0, .src_port = 0, .proto = 0}; 
        key.src_ip = src_ip; 
        key.proto = ip->protocol;
        u32 new_dst_ip;
        if (key.proto == IPPROTO_TCP) {
            struct tcphdr tcp;
            if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
                return TC_ACT_SHOT;
            key.src_port = tcp.source;
            // bpf_trace_printk("send tcp.source: %d\\n, tcp.dest: %d\\n", tcp.source, tcp.dest);
            struct ct_val *ct = ct_map.lookup(&key);
            if (ct == NULL) {
                u32 backend_ip = (bpf_get_prandom_u32() & 1)
                            ? bpf_htonl(NEW_DST_IP)
                            : bpf_htonl(NEW_DST_IP2);
                u16 rev = bpf_get_prandom_u32();
                struct ct_val new_ct = {
                    .backend_ip = backend_ip,
                    .backend_port = tcp.dest,
                    .rev_nat_index = rev,
                };
                struct rev_nat_val rev_val = {
                    .client_ip   = dst_ip,
                    .client_port = tcp.source,
                };
                ct_map.update(&key, &new_ct);
                rev_nat_map.update(&rev, &rev_val);

                ct = &new_ct;
                new_dst_ip = backend_ip;
            } else {
                new_dst_ip = ct->backend_ip;
            }
        } else if (key.proto == IPPROTO_UDP) {
            struct udphdr udp;
            if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
                return TC_ACT_SHOT;
            key.src_port = udp.source;
        }
        
        // Store the updated destination IP in the packet   
        if (bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, daddr), &new_dst_ip, sizeof(new_dst_ip), 0) < 0) {
            bpf_trace_printk("Failed to modify daddr\\n");
            bpf_trace_printk("bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, daddr), &new_dst_ip, sizeof(new_dst_ip), 0) < 0\\n");   
            return TC_ACT_SHOT;
        }

        if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), old_dstip, new_dst_ip, sizeof(new_dst_ip)) < 0) {
            bpf_trace_printk("Failed to update IP checksum\\n");
            return TC_ACT_SHOT;
        }

        u16 protocol = key.proto;
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {


            // Determine checksum offset based on protocol
            int csum_offset = (protocol == IPPROTO_TCP) ? 16 : 6;
            // int flags = (protocol == IPPROTO_UDP) ? BPF_F_PSEUDO_HDR : 0;  // UDP needs pseudo-header
            int flags = (protocol == IPPROTO_UDP) ? (BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0) : 0;

            // Check packet length
            if (skb->len < l4_offset + csum_offset + 2) {
                bpf_trace_printk("Packet too short for L4 checksum update\\n");
                return TC_ACT_SHOT;
            }
            if (bpf_skb_pull_data(skb, l4_offset + csum_offset + 2) < 0) {
                bpf_trace_printk("Failed to pull skb data\\n");
                return TC_ACT_SHOT;
            }
            // Update the L4 checksum
            flags = flags | 4;
            int ret = bpf_l4_csum_replace(skb, l4_offset + csum_offset, old_dstip, new_dst_ip, IS_PSEUDO | flags);
            if (ret < 0) {
                bpf_trace_printk("Failed to update L4 checksum %d\\n", ret);
                return TC_ACT_SHOT;
            }
        }
        return TC_ACT_OK;
    }   
   return TC_ACT_OK;
}

"""

def cleanup():
    print("\n[*] Detaching TC and cleaning up...")

    try:
        # 删除 ingress filters（两个 parent）
        ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff2")
        ipr.tc("del-filter", "bpf", idx1, ":1", parent="ffff:fff2")
        ipr.tc("del-filter", "bpf", idx2, ":1", parent="ffff:fff2")
    except Exception:
        pass

    # try:
    #     ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff3")
    #     ipr.tc("del-filter", "bpf", idx1, ":1", parent="ffff:fff3")
    #     ipr.tc("del-filter", "bpf", idx2, ":1", parent="ffff:fff3")
    # except Exception:
    #     pass

    try:
        # 删除 clsact qdisc
        ipr.tc("del", "clsact", idx)
        ipr.tc("del", "clsact", idx1)
        ipr.tc("del", "clsact", idx2)
    except Exception:
        pass

    if b:
        b.cleanup()

    print("[✓] Cleanup done.")
    
ipr = IPRoute()
interface = "lxc9923cb187ee9"
interface1 = "lxcd4e406e0a80c"
interface2 = "lxcc1f8888283b7"
# Ensure the interface exists
try:
   idx = ipr.link_lookup(ifname=interface)[0]
   idx1 = ipr.link_lookup(ifname=interface1)[0]
   idx2 = ipr.link_lookup(ifname=interface2)[0]
except IndexError:
   print(f"Error: Interface {interface} not found. Is it created?")
   exit(1)

# Ensure clsact qdisc is added only once
try:
    ipr.tc("add", "clsact", idx)
    ipr.tc("add", "clsact", idx1)
    ipr.tc("add", "clsact", idx2)
except Exception as e:
    print(f"clsact qdisc already exists: {e}")


# Attach to veth0 using TC
try:
    b = BPF(text=bpf_program)
    service_pod_mapping, services, pods = kube_query()
    # TODO: Add automatically later
    backend_set = b["backend_set"]
    backend_set[backend_set.Key(0x0A000132)] = backend_set.Leaf(1)  # 10.0.1.110
    backend_set[backend_set.Key(0x0A00012A)] = backend_set.Leaf(1)  # 10.0.1.42

    print(service_pod_mapping)
    fn = b.load_func("redirect_service", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

    fn = b.load_func("redirect_service", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx1, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

    fn = b.load_func("redirect_service", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx2, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

    print(f"BPF attached to {interface} - SCHED_CLS: OK")
    print("Waiting for packets... Press Ctrl+C to stop.")
    b.trace_print()
finally:
   cleanup()
