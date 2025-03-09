from bcc import BPF
from pyroute2 import IPRoute
import pyroute2


bpf_program = """
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>


#define SRC_IP 0x0AF40004  // 10.244.0.4 (hex representation)
#define SVCIP 0x0A604D4C  // 10.96.77.76 (hex representation)
#define NEW_DST_IP 0x0AF40104  // 10.244.1.4 (hex representation)

#define IS_PSEUDO 0x10

int redirect_service(struct __sk_buff *skb) {
   struct ethhdr eth;
   struct iphdr ip;
   int ip_offset = 14;

    // bpf_trace_printk("TC_ACT_OK = %d\\n", TC_ACT_OK = 0);
    // bpf_trace_printk("TC_ACT_SHOT = %d\\n", TC_ACT_SHOT = 2);
    
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


   if (src_ip == SRC_IP) {   
       if (dst_ip == SVCIP) {
           bpf_trace_printk("From tcingress vethe3e55ebf:\\n");
          
           bpf_trace_printk("Captured packet from source IP: %d.%d.%d\\n",
                           (src_ip >> 24) & 0xFF,
                           (src_ip >> 16) & 0xFF,
                           (src_ip >> 8) & 0xFF);
           bpf_trace_printk("Captured packet from source IP: %d.\\n", src_ip & 0xFF);


           bpf_trace_printk("Captured packet to destination IP: %d.%d.%d\\n",
                       (dst_ip >> 24) & 0xFF,
                       (dst_ip >> 16) & 0xFF,
                       (dst_ip >> 8) & 0xFF);
           bpf_trace_printk("Captured packet to destination IP: %d.\\n", dst_ip & 0xFF);
          
           // Store the updated destination IP in the packet   
           if (bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, daddr), &new_dst_ip, sizeof(new_dst_ip), 0) < 0) {
               bpf_trace_printk("Failed to modify daddr\\n");
               bpf_trace_printk("bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, daddr), &new_dst_ip, sizeof(new_dst_ip), 0) < 0\\n");   
               return TC_ACT_SHOT;
           }
            struct iphdr updated_ip;
            if (bpf_skb_load_bytes(skb, ip_offset, &updated_ip, sizeof(updated_ip)) < 0) {
                bpf_trace_printk("Failed to load updated IP header\\n");
                return TC_ACT_SHOT;
            }
           bpf_trace_printk("Got a packet from interface, 0x%x\\n", updated_ip.daddr);
           bpf_trace_printk("New destination IP: %d.%d.%d\\n",
                           (bpf_ntohl(updated_ip.daddr) >> 24) & 0xFF,
                           (bpf_ntohl(updated_ip.daddr) >> 16) & 0xFF,
                           (bpf_ntohl(updated_ip.daddr) >> 8) & 0xFF);
           bpf_trace_printk("New destination IP: %d.\\n", bpf_ntohl(updated_ip.daddr) & 0xFF);
          
          
           if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), ip.daddr, new_dst_ip, sizeof(new_dst_ip)) < 0) {
              bpf_trace_printk("Failed to update IP checksum\\n");
              return TC_ACT_SHOT;
           }
           if (ip.ihl < 5) {
                bpf_trace_printk("Invalid IP header length: %d\\n", ip.ihl);
                return TC_ACT_SHOT;
            }
            /*
            if (bpf_l4_csum_replace(skb, 34 + 16, ip.daddr, new_dst_ip, sizeof(u32)) < 0) {
                bpf_trace_printk("bpf_l4_csum_replace(skb, 14 + 16, ip.daddr, new_dst_ip, sizeof(u32)) < 0\\n");
                return TC_ACT_SHOT;
            }*/

            
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

    // bpf_trace_printk("TC_ACT_OK = %d\\n", TC_ACT_OK = 0);
    // bpf_trace_printk("TC_ACT_SHOT = %d\\n", TC_ACT_SHOT = 2);
    
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
       if (src_ip == NEW_DST_IP) {
           bpf_trace_printk("From tctry cni0:\\n");
          
           bpf_trace_printk("Captured packet from source IP: %d.%d.%d\\n",
                           (src_ip >> 24) & 0xFF,
                           (src_ip >> 16) & 0xFF,
                           (src_ip >> 8) & 0xFF);
           bpf_trace_printk("Captured packet from source IP: %d.\\n", src_ip & 0xFF);


           bpf_trace_printk("Captured packet to destination IP: %d.%d.%d\\n",
                       (dst_ip >> 24) & 0xFF,
                       (dst_ip >> 16) & 0xFF,
                       (dst_ip >> 8) & 0xFF);
           bpf_trace_printk("Captured packet to destination IP: %d.\\n", dst_ip & 0xFF);
          
           // Store the updated destination IP in the packet   
           if (bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, saddr), &new_src_ip, sizeof(new_src_ip), 0) < 0) {
               bpf_trace_printk("Failed to modify saddr\\n");
               bpf_trace_printk("bpf_skb_store_bytes(skb, ip_offset + offsetof(struct iphdr, saddr), &new_src_ip, sizeof(new_src_ip), 0) < 0\\n");   
               return TC_ACT_SHOT;
           }
            struct iphdr updated_ip;
            if (bpf_skb_load_bytes(skb, ip_offset, &updated_ip, sizeof(updated_ip)) < 0) {
                bpf_trace_printk("Failed to load updated IP header\\n");
                return TC_ACT_SHOT;
            }
           bpf_trace_printk("New destination IP: %d.%d.%d\\n",
                           (bpf_ntohl(updated_ip.saddr) >> 24) & 0xFF,
                           (bpf_ntohl(updated_ip.saddr) >> 16) & 0xFF,
                           (bpf_ntohl(updated_ip.saddr) >> 8) & 0xFF);
           bpf_trace_printk("New destination IP: %d.\\n", bpf_ntohl(updated_ip.saddr) & 0xFF);
          
          
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


ipr = IPRoute()
interface = "vethe3e55ebf"


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
   print("Exiting... No interface deletion performed. Please run \'sudo tc qdisc del dev " + interface + " clsact\' before running this eBPF program again")