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
#define SVCIP 0x0A6BB4B3  // 10.107.180.179 (hex representation)
#define NEW_DST_IP 0x0A000196  // 10.0.1.150 (hex representation)
#define NEW_DST_IP2 0x0A000165  // 10.0.1.101

#define IS_PSEUDO 0x10
#define FLOW_TIMEOUT_NS (120ULL * 1000 * 1000 * 1000)

struct flow_key {
    u32 src_ip;
    u16 src_port;
    u8  proto;
};

struct flow_val {
    u32 pod_ip;
    u64 last_seen_ns;
};

struct svc_val {
    u32 svc_ip;
    u64 last_seen_ns;
};

enum ct_state {
    CT_NEW = 0,
    CT_ESTABLISHED = 1,
};

struct ct_val {
    u8  state;
    u64 last_seen_ns;
};

BPF_TABLE("lru_hash", struct flow_key, struct ct_val, ct_map, 65536);
BPF_TABLE("lru_hash", struct flow_key, struct flow_val, dnat_map, 65536);
BPF_TABLE("lru_hash", struct flow_key, struct svc_val, snat_map, 65536);

// BPF_HASH(dnat_map, struct flow_key, struct flow_val);
// BPF_HASH(snat_map, struct flow_key, struct svc_val);

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
    // int ifindex = skb->ifindex;
    // bpf_trace_printk("redirect_service tc_ingress on ifindex=%d\\n", ifindex);
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

   if (src_ip == SRC_IP) {   
       if (dst_ip == SVCIP) {
            struct flow_key key = { .src_ip = 0, .src_port = 0, .proto = 0}; 
            key.src_ip = src_ip; 
            key.proto = ip.protocol;
            int l4_offset = sizeof(struct ethhdr) + (ip.ihl * 4);
            u32 new_dst_ip;
            if (ip.protocol == IPPROTO_TCP) {
                struct tcphdr tcp;
                if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
                    return TC_ACT_SHOT;
                key.src_port = tcp.source;
                // bpf_trace_printk("send tcp.source: %d\\n, tcp.dest: %d\\n", tcp.source, tcp.dest);
                if (tcp.syn && !tcp.ack) {
                    u32 rand_val = bpf_get_prandom_u32() % 10;
                    if (rand_val < 5) {
                        new_dst_ip = bpf_htonl(NEW_DST_IP2);
                    } else {
                        new_dst_ip = bpf_htonl(NEW_DST_IP);
                    }
                    struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                    struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                    dnat_map.update(&key, &new_val);
                    snat_map.update(&key, &svc_val);
                } else {
                    u64 now = bpf_ktime_get_ns();

                    struct flow_val *val = dnat_map.lookup(&key);
                    struct svc_val  *svc = snat_map.lookup(&key);

                    if (!val || !svc) {
                        if (val) dnat_map.delete(&key);
                        if (svc) snat_map.delete(&key);
                        u32 rand_val = bpf_get_prandom_u32() % 10;
                        if (rand_val < 5) {
                            new_dst_ip = bpf_htonl(NEW_DST_IP2);
                        } else {
                            new_dst_ip = bpf_htonl(NEW_DST_IP);
                        }
                        struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                        struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                        dnat_map.update(&key, &new_val);
                        snat_map.update(&key, &svc_val); 
                    } else if (now - val->last_seen_ns > FLOW_TIMEOUT_NS ||
                        now - svc->last_seen_ns > FLOW_TIMEOUT_NS) {
                        dnat_map.delete(&key);
                        snat_map.delete(&key);
                        u32 rand_val = bpf_get_prandom_u32() % 10;
                        if (rand_val < 5) {
                            new_dst_ip = bpf_htonl(NEW_DST_IP2);
                        } else {
                            new_dst_ip = bpf_htonl(NEW_DST_IP);
                        }
                        struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                        struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                        dnat_map.update(&key, &new_val);
                        snat_map.update(&key, &svc_val); 
                    } else {
                        val->last_seen_ns = now;
                        svc->last_seen_ns = now;
                        
                        new_dst_ip = val->pod_ip;     
                    }
                    if (tcp.fin || tcp.rst) {
                        dnat_map.delete(&key);
                    }
                }
            } else if (ip.protocol == IPPROTO_UDP) {
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
          
           if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), ip.daddr, new_dst_ip, sizeof(new_dst_ip)) < 0) {
              bpf_trace_printk("Failed to update IP checksum\\n");
              return TC_ACT_SHOT;
           }
           if (ip.ihl < 5) {
                bpf_trace_printk("Invalid IP header length: %d\\n", ip.ihl);
                return TC_ACT_SHOT;
            }
            
           u16 protocol = ip.protocol;
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

int redirect_service1(struct __sk_buff *skb) {
    // int ifindex = skb->ifindex;
    // bpf_trace_printk("redirect_service1 tc_ingress on ifindex=%d\\n", ifindex);
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

   if (src_ip == NEW_DST_IP) {   
       if (dst_ip == SVCIP) {
            struct flow_key key = { .src_ip = 0, .src_port = 0, .proto = 0}; 
            key.src_ip = src_ip; 
            key.proto = ip.protocol;
            int l4_offset = sizeof(struct ethhdr) + (ip.ihl * 4);
            u32 new_dst_ip;
            if (ip.protocol == IPPROTO_TCP) {
                struct tcphdr tcp;
                if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
                    return TC_ACT_SHOT;
                key.src_port = tcp.source;
                // bpf_trace_printk("send tcp.source: %d\\n, tcp.dest: %d\\n", tcp.source, tcp.dest);
                if (tcp.syn && !tcp.ack) {
                    u32 rand_val = bpf_get_prandom_u32() % 10;
                    if (rand_val < 5) {
                        new_dst_ip = bpf_htonl(NEW_DST_IP2);
                    } else {
                        new_dst_ip = bpf_htonl(NEW_DST_IP);
                    }
                    struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                    struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                    dnat_map.update(&key, &new_val);
                    snat_map.update(&key, &svc_val);
                } else {
                    u64 now = bpf_ktime_get_ns();

                    struct flow_val *val = dnat_map.lookup(&key);
                    struct svc_val  *svc = snat_map.lookup(&key);

                    if (!val || !svc) {
                        if (val) dnat_map.delete(&key);
                        if (svc) snat_map.delete(&key);
                        u32 rand_val = bpf_get_prandom_u32() % 10;
                        if (rand_val < 5) {
                            new_dst_ip = bpf_htonl(NEW_DST_IP2);
                        } else {
                            new_dst_ip = bpf_htonl(NEW_DST_IP);
                        }
                        struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                        struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                        dnat_map.update(&key, &new_val);
                        snat_map.update(&key, &svc_val); 
                    } else if (now - val->last_seen_ns > FLOW_TIMEOUT_NS ||
                        now - svc->last_seen_ns > FLOW_TIMEOUT_NS) {
                        dnat_map.delete(&key);
                        snat_map.delete(&key);
                        u32 rand_val = bpf_get_prandom_u32() % 10;
                        if (rand_val < 5) {
                            new_dst_ip = bpf_htonl(NEW_DST_IP2);
                        } else {
                            new_dst_ip = bpf_htonl(NEW_DST_IP);
                        }
                        struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                        struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                        dnat_map.update(&key, &new_val);
                        snat_map.update(&key, &svc_val); 
                    } else {
                        val->last_seen_ns = now;
                        svc->last_seen_ns = now;
                        
                        new_dst_ip = val->pod_ip;     
                    }
                    if (tcp.fin || tcp.rst) {
                        dnat_map.delete(&key);
                    }
                }
            } else if (ip.protocol == IPPROTO_UDP) {
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
          
           if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), ip.daddr, new_dst_ip, sizeof(new_dst_ip)) < 0) {
              bpf_trace_printk("Failed to update IP checksum\\n");
              return TC_ACT_SHOT;
           }
           if (ip.ihl < 5) {
                bpf_trace_printk("Invalid IP header length: %d\\n", ip.ihl);
                return TC_ACT_SHOT;
            }
            
           u16 protocol = ip.protocol;
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

int redirect_service2(struct __sk_buff *skb) {
    // int ifindex = skb->ifindex;
    // bpf_trace_printk("redirect_service2 tc_ingress on ifindex=%d\\n", ifindex);
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

   if (src_ip == NEW_DST_IP2) {   
       if (dst_ip == SVCIP) {
            struct flow_key key = { .src_ip = 0, .src_port = 0, .proto = 0}; 
            key.src_ip = src_ip; 
            key.proto = ip.protocol;
            int l4_offset = sizeof(struct ethhdr) + (ip.ihl * 4);
            u32 new_dst_ip;
            if (ip.protocol == IPPROTO_TCP) {
                struct tcphdr tcp;
                if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
                    return TC_ACT_SHOT;
                key.src_port = tcp.source;
                // bpf_trace_printk("send tcp.source: %d\\n, tcp.dest: %d\\n", tcp.source, tcp.dest);
                if (tcp.syn && !tcp.ack) {
                    u32 rand_val = bpf_get_prandom_u32() % 10;
                    if (rand_val < 5) {
                        new_dst_ip = bpf_htonl(NEW_DST_IP2);
                    } else {
                        new_dst_ip = bpf_htonl(NEW_DST_IP);
                    }
                    struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                    struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                    dnat_map.update(&key, &new_val);
                    snat_map.update(&key, &svc_val);
                } else {
                    u64 now = bpf_ktime_get_ns();

                    struct flow_val *val = dnat_map.lookup(&key);
                    struct svc_val  *svc = snat_map.lookup(&key);

                    if (!val || !svc) {
                        if (val) dnat_map.delete(&key);
                        if (svc) snat_map.delete(&key);
                        u32 rand_val = bpf_get_prandom_u32() % 10;
                        if (rand_val < 5) {
                            new_dst_ip = bpf_htonl(NEW_DST_IP2);
                        } else {
                            new_dst_ip = bpf_htonl(NEW_DST_IP);
                        }
                        struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                        struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                        dnat_map.update(&key, &new_val);
                        snat_map.update(&key, &svc_val); 
                    } else if (now - val->last_seen_ns > FLOW_TIMEOUT_NS ||
                        now - svc->last_seen_ns > FLOW_TIMEOUT_NS) {
                        dnat_map.delete(&key);
                        snat_map.delete(&key);
                        u32 rand_val = bpf_get_prandom_u32() % 10;
                        if (rand_val < 5) {
                            new_dst_ip = bpf_htonl(NEW_DST_IP2);
                        } else {
                            new_dst_ip = bpf_htonl(NEW_DST_IP);
                        }
                        struct flow_val new_val = { .pod_ip = new_dst_ip, .last_seen_ns = bpf_ktime_get_ns() };
                        struct svc_val svc_val = { .svc_ip = bpf_htonl(SVCIP), .last_seen_ns = bpf_ktime_get_ns() };
                        dnat_map.update(&key, &new_val);
                        snat_map.update(&key, &svc_val); 
                    } else {
                        val->last_seen_ns = now;
                        svc->last_seen_ns = now;
                        
                        new_dst_ip = val->pod_ip;     
                    }
                    if (tcp.fin || tcp.rst) {
                        dnat_map.delete(&key);
                    }
                }
            } else if (ip.protocol == IPPROTO_UDP) {
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
          
           if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), ip.daddr, new_dst_ip, sizeof(new_dst_ip)) < 0) {
              bpf_trace_printk("Failed to update IP checksum\\n");
              return TC_ACT_SHOT;
           }
           if (ip.ihl < 5) {
                bpf_trace_printk("Invalid IP header length: %d\\n", ip.ihl);
                return TC_ACT_SHOT;
            }
            
           u16 protocol = ip.protocol;
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
    // int ifindex = skb->ifindex;
    // bpf_trace_printk("redirect_pod_to_service tc_egress on ifindex=%d\\n", ifindex);
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
   u32 new_src_ip;
   
   struct flow_key key = { .src_ip = 0, .src_port = 0, .proto = 0};
   key.src_ip = dst_ip;
   key.proto = ip.protocol;
   int l4_offset = sizeof(struct ethhdr) + (ip.ihl * 4);
   
   if (ip.protocol == IPPROTO_TCP) {
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
        return TC_ACT_SHOT;
    key.src_port = tcp.dest;
    // bpf_trace_printk("reply tcp.source: %d\\n, tcp.dest: %d\\n", tcp.source, tcp.dest);
   }
   
   struct svc_val *svc = snat_map.lookup(&key);
   if (svc != NULL) {
        new_src_ip = svc->svc_ip;
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

    try:
        ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff3")
        ipr.tc("del-filter", "bpf", idx1, ":1", parent="ffff:fff3")
        ipr.tc("del-filter", "bpf", idx2, ":1", parent="ffff:fff3")
    except Exception:
        pass

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
interface1 = "lxcb2e7d031b076"
interface2 = "lxce47557175acb"
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
    print(service_pod_mapping)
    fn = b.load_func("redirect_service", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

    fn = b.load_func("redirect_pod_to_service", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1)

    fn = b.load_func("redirect_service1", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx1, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

    fn = b.load_func("redirect_pod_to_service", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx1, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1)

    fn = b.load_func("redirect_service2", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx2, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

    fn = b.load_func("redirect_pod_to_service", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx2, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1)

    print(f"BPF attached to {interface} - SCHED_CLS: OK")
    print("Waiting for packets... Press Ctrl+C to stop.")
    b.trace_print()
finally:
   cleanup()
