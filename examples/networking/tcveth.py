from bcc import BPF
from pyroute2 import IPRoute
import pyroute2


bpf_program = """
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <linux/udp.h>
#include <linux/tcp.h> // --> struct tcphdr tcp;


#define SRC_IP 0x0A000194  // 10.0.1.148 (hex representation)
#define SVCIP 0x0A6BB4B3  // 10.107.180.179 (hex representation)
#define NEW_DST_IP 0x0A000196  // 10.0.1.150 (hex representation)
#define NEW_DST_IP2 0x0A000165  // 10.0.1.101

#define IS_PSEUDO 0x10


struct flow_key {
    u32 src_ip;
    u16 src_port;
    u16 dst_port;
    u8  proto;
};

struct flow_val {
    u32 pod_ip;
    u64 last_seen_ns;
};

BPF_HASH(dnat_map, struct flow_key, struct flow_val);

static inline int parse_l4(struct __sk_buff *skb, struct iphdr *ip, u16 *src_port, u16 *dst_port) {
    u8 proto = ip->protocol;
    int l4_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

    if (proto == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
            return -1;
        *src_port = tcp.source;
        *dst_port = tcp.dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
            return -1;
        *src_port = udp.source;
        *dst_port = udp.dest;
    } else {
        return -1;
    }
    return 0;
}

int redirect_service(struct __sk_buff *skb) {
   struct ethhdr eth;
   struct iphdr ip;
   int ip_offset = 14;
    
   if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
       return TC_ACT_OK;


   if (eth.h_proto != bpf_htons(ETH_P_IP))
       return TC_ACT_OK;


   if (bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(ip)) < 0)
       return TC_ACT_OK;


    u32 dst_ip = bpf_ntohl(ip.daddr);
   u32 src_ip = bpf_ntohl(ip.saddr);     



   struct flow_key key = { .src_ip = 0, .src_port = 0, .dst_port = 0, .proto = 0}; 
   key.src_ip = src_ip; 
   key.proto = ip.protocol;
   u16 dst_port;
    if (parse_l4(skb, &ip, &key.src_port, &key.dst_port) < 0) {
        bpf_trace_printk("parse_l4(skb, &ip, &key.src_port, &key.dst_port) < 0\\n");
        return TC_ACT_OK;
    }
    struct flow_val *val = dnat_map.lookup(&key);
    u32 new_dst_ip;
    if (val != NULL) {
        bpf_trace_printk("dnat_map.lookup(&key) == NULL\\n");
        new_dst_ip = val->pod_ip;     
    } else {
        u32 rand_val = bpf_get_prandom_u32() % 10;
        if (rand_val < 5) {
            new_dst_ip = bpf_htonl(NEW_DST_IP2);
            bpf_trace_printk("rand_val < 5 --> NEW_DST_IP2\\n");
        } else {
            new_dst_ip = bpf_htonl(NEW_DST_IP);
            bpf_trace_printk("rand_val >= 5 --> NEW_DST_IP\\n");
        }
        struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
        dnat_map.update(&key, &new_val);
    }

   
   
   
   /* u32 new_dst_ip = bpf_htonl(NEW_DST_IP); */

   if (src_ip == SRC_IP) {   
       if (dst_ip == SVCIP) {
          
           // Store the updated destination IP in the packet   
           if (bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, daddr), &new_dst_ip, sizeof(new_dst_ip), 0) < 0) {
               bpf_trace_printk("Failed to modify daddr\\n");
               bpf_trace_printk("bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, daddr), &new_dst_ip, sizeof(new_dst_ip), 0) < 0\\n");   
               return TC_ACT_SHOT;
           }
          
           if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), ip.daddr, new_dst_ip, sizeof(new_dst_ip)) < 0) {
              bpf_trace_printk("Failed to update IP checksum\\n");
              return TC_ACT_SHOT;
           }
           if (ip.ihl < 5) {
                bpf_trace_printk("Invalid IP header length: %d\\n", ip.ihl);
                return TC_ACT_SHOT;
            }
            
           u16 protocol = ip.protocol;
           int l4_offset = ip_offset + (ip.ihl * 4);  // Compute L4 header offset
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
               int ret = bpf_l4_csum_replace(skb, l4_offset + csum_offset, ip.daddr, new_dst_ip, IS_PSEUDO | flags);
               if (ret < 0) {
                  bpf_trace_printk("Failed to update L4 checksum %d\\n", ret);
                   return TC_ACT_SHOT;
               }
           }
       }   
   }
   return TC_ACT_OK;
}

int redirect_pod_to_service(struct __sk_buff *skb) {
   struct ethhdr eth;
   struct iphdr ip;
   int ip_offset = 14;
    
   if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
       return TC_ACT_OK;


   if (eth.h_proto != bpf_htons(ETH_P_IP))
       return TC_ACT_OK;


   if (bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(ip)) < 0)
       return TC_ACT_OK;


   u32 dst_ip = bpf_ntohl(ip.daddr);
   u32 src_ip = bpf_ntohl(ip.saddr);
   u32 new_dst_ip = bpf_htonl(NEW_DST_IP);
   u32 new_src_ip = bpf_htonl(SVCIP);  // Pretend to be the service IP
   if (dst_ip == SRC_IP) {   
       if (src_ip == NEW_DST_IP || src_ip == NEW_DST_IP2) {
       // if (src_ip == NEW_DST_IP) {
           // Store the updated destination IP in the packet   
           if (bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, saddr), &new_src_ip, sizeof(new_src_ip), 0) < 0) {
               bpf_trace_printk("Failed to modify saddr\\n");
               bpf_trace_printk("bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, saddr), &new_src_ip, sizeof(new_src_ip), 0) < 0\\n");   
               return TC_ACT_SHOT;
           }
          
           if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), ip.saddr, new_src_ip, sizeof(new_src_ip)) < 0) {
              bpf_trace_printk("Failed to update IP l3 checksum\\n");
              return TC_ACT_SHOT;
           }
           if (ip.ihl < 5) {
                bpf_trace_printk("Invalid IP header length: %d\\n", ip.ihl);
                return TC_ACT_SHOT;
            }

            
           u16 protocol = ip.protocol;
           if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
               int l4_offset = ip_offset + (ip.ihl * 4);  // Compute L4 header offset


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
               int ret = bpf_l4_csum_replace(skb, l4_offset + csum_offset, ip.saddr, new_src_ip, IS_PSEUDO | flags);
               if (ret < 0) {
                  bpf_trace_printk("Failed to update L4 checksum %d\\n", ret);
                   return TC_ACT_SHOT;
               }
           }
            
       }   
   }
   return TC_ACT_OK;
}


"""

def cleanup():
    print("\n[*] Detaching TC and cleaning up...")

    try:
        # 删除 ingress filters（两个 parent）
        ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff2")
    except Exception:
        pass

    try:
        ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff3")
    except Exception:
        pass

    try:
        # 删除 clsact qdisc
        ipr.tc("del", "clsact", idx)
    except Exception:
        pass

    if b:
        b.cleanup()

    print("[✓] Cleanup done.")

ipr = IPRoute()
interface = "lxc9923cb187ee9"


# Ensure the interface exists
try:
   idx = ipr.link_lookup(ifname=interface)[0]
except IndexError:
   print(f"Error: Interface {interface} not found. Is it created?")
   exit(1)


# # Ensure cleanup of the existing ingress qdisc
# try:
#     ipr.tc("del", "ingress", idx)  # Remove existing ingress qdisc
# except pyroute2.netlink.exceptions.NetlinkError:
#     pass  # In case it doesn't exist



# Ensure clsact qdisc is added only once
try:
    ipr.tc("add", "clsact", idx)
except Exception as e:
    print(f"clsact qdisc already exists: {e}")


# Attach to veth0 using TC
try:
   b = BPF(text=bpf_program)
   fn = b.load_func("redirect_service", BPF.SCHED_CLS)
   ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

   fn = b.load_func("redirect_pod_to_service", BPF.SCHED_CLS)
   ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1)

   print(f"BPF attached to {interface} - SCHED_CLS: OK")
   print("Waiting for packets... Press Ctrl+C to stop.")
   b.trace_print()
finally:
   cleanup()