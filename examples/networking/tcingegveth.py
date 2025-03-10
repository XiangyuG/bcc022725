from bcc import BPF
from pyroute2 import IPRoute
import pyroute2
from multiprocessing import Process

from kubernetes import client, config
import ctypes

bpf_program = """
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
// Use uapi version of tcp.h and udp.h
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

// Define a struct for the key (source IP + port)
struct ip_port_key {
    u32 ip;
    u16 port;
};

// Define a map using BPF_HASH
BPF_HASH(dnat_map, struct ip_port_key, u32);
BPF_HASH(time_dnat, struct ip_port_key, u64);
BPF_HASH(snat_map, u32, u32); // server pod IP --> frontend pod IP

BPF_ARRAY(rr_index, u32, 1);
BPF_HASH(frontend_svc);
BPF_HASH(frontend_pod, u32, u32);
BPF_HASH(kubernetes_svc);
BPF_HASH(server_svc, u32, u32);
BPF_HASH(server_pod, u32, u32);

// #define SRC_IP 0x0AF40004  // 10.244.0.4 (hex representation)
// #define SVCIP 0x0A604D4C  // 10.96.77.76 (hex representation)
// #define NEW_DST_IP 0x0AF40104  // 10.244.1.4 (hex representation)
// #define NEW_DST_IP_POD2 0x0AF40102  // 10.244.1.2 (hex representation)


#define IS_PSEUDO 0x10

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
    // Get svcip first
    u32 svcip = 0;
    u32 svcip_key = 0;
    u32 *value = server_svc.lookup(&svcip_key);
    if (value) {
        svcip = (*value);
    }

   u32 frontendPodIP = 0;
   u32 frontendPod_key = 0;
   u32 *frontendPodValue = frontend_pod.lookup(&frontendPod_key);
   if (frontendPodValue) {
        frontendPodIP = (*frontendPodValue);
   }

   
   u32 serverPod0IP = 0;
   u32 serverPod1IP = 0;
   u32 serverPod2IP = 0;
   u32 serverPod0_key = 0;
   u32 serverPod1_key = 1;
   u32 serverPod2_key = 2;
   u32 *serverPod0Value = server_pod.lookup(&serverPod0_key);
   u32 *serverPod1Value = server_pod.lookup(&serverPod1_key);
   u32 *serverPod2Value = server_pod.lookup(&serverPod2_key);
   if (serverPod0Value) {
        serverPod0IP = (*serverPod0Value);
   }
   if (serverPod1Value) {
        serverPod1IP = (*serverPod1Value);
   }
   if (serverPod2Value) {
        serverPod2IP = (*serverPod2Value);
   }

   u64 expiration = 30ULL * 1000000000ULL;  // 30 seconds in nanoseconds
   struct ethhdr eth;
   struct iphdr ip;
   // We have to initialize the key before updating it
   struct ip_port_key key = { .ip = 0, .port = 12345 }; 
   int ip_offset = 14;
    
   if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
       return TC_ACT_OK;

   if (eth.h_proto != bpf_htons(ETH_P_IP))
       return TC_ACT_OK;

   if (bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(ip)) < 0)
       return TC_ACT_OK;
   

   u32 dst_ip = bpf_ntohl(ip.daddr);
   u32 src_ip = bpf_ntohl(ip.saddr);
   u32 new_dst_ip = bpf_htonl(serverPod1IP);
   u32 new_dst_ip_2 = bpf_htonl(serverPod2IP);
        
   // Src: 10.244.0.4; Dst: 10.96.77.76
   if (src_ip == frontendPodIP) {   
       if (dst_ip == svcip) {
           bpf_trace_printk("From tcingress vethe3e55ebf:\\n");
           // Get the source IP and source port ID
           key.ip = src_ip; 
            u16 src_port;
            if (parse_l4(skb, &ip, &key.port, &src_port) < 0) {
                    bpf_trace_printk("parse_l4(skb, &ip, &key.port, &src_port) < 0\\n");
                    return TC_ACT_OK;
            }
            bpf_trace_printk("port ID is %d\\n", key.port);
           u32 *exist_dst_ip = dnat_map.lookup(&key);
           if (exist_dst_ip) {
              bpf_trace_printk("Exist", exist_dst_ip);
              new_dst_ip = (*exist_dst_ip);
              u64 *pre_time = time_dnat.lookup(&key);
              if (pre_time) {
                u64 now = bpf_ktime_get_ns();
                if (now - (*pre_time) > expiration) {
                    bpf_trace_printk("Need update\\n");
                    if (key.port % 2 == 0) {
                        new_dst_ip = bpf_htonl(serverPod1IP);
                    } else {
                        new_dst_ip = bpf_htonl(serverPod2IP);
                    }
                    dnat_map.update(&key, &new_dst_ip);
                    time_dnat.update(&key, &now);
                }
              } else {
                new_dst_ip = (*exist_dst_ip);
              }
           } else {
              
              // u32 rand_val = bpf_get_prandom_u32() % 10; // Generate a pseudo-random number
              // Choose the target pod in a round robin fashion
              u32 pod_select_key = 0;
              u32 *pod_index = rr_index.lookup(&pod_select_key);
              if (pod_index) {
                if (*pod_index == 0) {
                    u32 key0 = 0;
                    u32 *ip0 = server_pod.lookup(&key0);
                    if (ip0) {
                        new_dst_ip = bpf_htonl(*ip0);
                    }
                } else if (*pod_index == 1) {
                    u32 key1 = 1;
                    u32 *ip1 = server_pod.lookup(&key1);
                    if (ip1) {
                        new_dst_ip = bpf_htonl(*ip1);
                    }
                } else if (*pod_index == 2) {
                    u32 key2 = 2;
                    u32 *ip2 = server_pod.lookup(&key2);
                    if (ip2) {
                        new_dst_ip = bpf_htonl(*ip2);
                    }
                }
                *pod_index = (*pod_index + 1) % 3;
                rr_index.update(&pod_select_key, pod_index);
              }
              
              /*
              if (key.port % 2 == 0) {
                 new_dst_ip = bpf_htonl(serverPod1IP);
              } else {
                 new_dst_ip = bpf_htonl(serverPod2IP);
              }
              */
              dnat_map.update(&key, &new_dst_ip);
              u64 now = bpf_ktime_get_ns();
              time_dnat.update(&key, &now);
              snat_map.update(&new_dst_ip, &src_ip);
              bpf_trace_printk("Does not exist\\n");
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

   // Get svcip first
    u32 svcip = 0;
    u32 svcip_key = 0;
    u32 *value = server_svc.lookup(&svcip_key);
    if (value) {
        svcip = (*value);
    }
   u32 frontendPodIP = 0;
   u32 frontendPod_key = 0;
   u32 *frontendPodValue = frontend_pod.lookup(&frontendPod_key);
   if (frontendPodValue) {
        frontendPodIP = (*frontendPodValue);
   }

   u32 serverPod0IP = 0;
   u32 serverPod1IP = 0;
   u32 serverPod2IP = 0;
   u32 serverPod0_key = 0;
   u32 serverPod1_key = 1;
   u32 serverPod2_key = 2;
   u32 *serverPod0Value = server_pod.lookup(&serverPod0_key);
   u32 *serverPod1Value = server_pod.lookup(&serverPod1_key);
   u32 *serverPod2Value = server_pod.lookup(&serverPod2_key);
   if (serverPod0Value) {
        serverPod0IP = (*serverPod0Value);
   }
   if (serverPod1Value) {
        serverPod1IP = (*serverPod1Value);
   }
   if (serverPod2Value) {
        serverPod2IP = (*serverPod2Value);
   }

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
   u32 new_dst_ip = bpf_htonl(serverPod1IP);
   u32 new_src_ip = 0;  // Pretend to be the service IP
   // destination IP is 10.244.0.4
   if (dst_ip == frontendPodIP) {   
       if (src_ip == serverPod0IP || src_ip == serverPod1IP || src_ip == serverPod2IP) {
           bpf_trace_printk("From tcegress vethe3e55ebf:\\n");
                  
           bpf_trace_printk("Captured packet from source IP: %d.%d.%d\\n",
                           (src_ip >> 24) & 0xFF,
                           (src_ip >> 16) & 0xFF,
                           (src_ip >> 8) & 0xFF);
           bpf_trace_printk("Captured packet from source IP: %d.\\n", src_ip & 0xFF);

           u32 *frontend_pod_ip = snat_map.lookup(&ip.saddr);
           if (frontend_pod_ip) {
                bpf_trace_printk("SNAT Map\\n");
                new_src_ip = bpf_htonl(svcip);
           }

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

def ip_to_hex(ip):
    """Convert IP string (e.g., 10.244.0.4) to hex integer."""
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

'''Get IPs for all services and pods; get the mapping from service to all its pods'''
def get_kubernetes_info():
    # Load Kubernetes config (use `config.load_incluster_config()` if running inside a cluster)
    config.load_kube_config()

    v1 = client.CoreV1Api()

    namespace = "default"  # Change this to your namespace

    # Get all services in the namespace
    services = v1.list_namespaced_service(namespace)

    # Get all pods in the namespace
    pods = v1.list_namespaced_pod(namespace)

    # for pod in pods.items:
    #     print(f"Pod: {pod.metadata.name}, IP: {pod.status.pod_ip}", "hex_ip", ip_to_hex(pod.status.pod_ip))

    # Get all services in the same namespace
    services = v1.list_namespaced_service(namespace)
    # for svc in services.items:
    #     print(f"Service: {svc.metadata.name}, Cluster IP: {svc.spec.cluster_ip}", "hex_ip", ip_to_hex(svc.spec.cluster_ip))


    # Create a mapping of pod name -> labels
    pod_map = {pod.metadata.name: pod.metadata.labels for pod in pods.items}

    # Iterate over each service to find matching pods
    service_pod_mapping = {}

    for svc in services.items:
        svc_name = svc.metadata.name
        svc_ip = svc.spec.cluster_ip
        svc_selector = svc.spec.selector

        if not svc_selector:
            # print(f"Service {svc_name} has no selectors (it may be an ExternalName service).")
            continue

        # Convert service selectors to key=value format
        label_selector = ",".join([f"{k}={v}" for k, v in svc_selector.items()])

        # Find matching pods
        matching_pods = [
            pod_name for pod_name, labels in pod_map.items()
            if labels and all(labels.get(k) == v for k, v in svc_selector.items())
        ]

        service_pod_mapping[svc_name] = matching_pods
    return service_pod_mapping, services, pods

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
   # Populate service and pod map
   service_pod_mapping, services, pods = get_kubernetes_info()

   rr_index = b["rr_index"]
   rr_index[ctypes.c_uint(0)] = ctypes.c_uint(0)
   for service in services.items:
        service_map = b[service.metadata.name+"_svc"]
        service_map[ctypes.c_uint32(0)] = ctypes.c_uint32(ip_to_hex(service.spec.cluster_ip)) # bcc requires a ctypes instance
   for svc, all_pods in service_pod_mapping.items():
        service_pod_map = b[svc + "_pod"]
        for i in range(len(all_pods)):
            for pod in pods.items:
                if all_pods[i] == pod.metadata.name:
                    service_pod_map[ctypes.c_uint32(i)] = ctypes.c_uint32(ip_to_hex(pod.status.pod_ip))
                    break

   fn = b.load_func("redirect_service", BPF.SCHED_CLS)
   ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)

   fn = b.load_func("redirect_pod_to_service", BPF.SCHED_CLS)
   ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1)

   print(f"BPF attached to {interface} - SCHED_CLS: OK")
   print("Waiting for packets... Press Ctrl+C to stop.")
   b.trace_print()
finally:
   print("Exiting... No interface deletion performed. Please run \'sudo tc qdisc del dev " + interface + " clsact\' before running this eBPF program again")