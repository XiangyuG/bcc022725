import bcc
from bcc import BPF
import socket
import ctypes
from kubernetes import client, config

import time
# Define the eBPF C code
bpf_code = """
// #include <linux/bpf.h>
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#include <linux/in.h>

BPF_ARRAY(limit_rate, u32, 1);
BPF_ARRAY(token_rate, u32, 1);
BPF_ARRAY(per_sec_rate, u32, 1);

BPF_HASH(frontend_pod, u32, u32);
BPF_HASH(server_pod, u32, u32);

BPF_HASH(time_map, u32, u64);

int drop_packet(struct xdp_md *ctx) {
    // Access the Ethernet header
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    // Check if the Ethernet header is valid and that it's an IPv4 packet
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;  // If the packet is too short to have an Ethernet header, pass

    if (eth->h_proto == htons(ETH_P_IP)) {  // If it's an IPv4 packet
        // Access the IP header
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check that the IP header is valid and the packet is large enough
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;  // If the packet is too short to have an IP header, pass

        // Extract the source IP address (htonl converts to readable format)
        u32 src_ip = ip->saddr;
        u32 dst_ip = bpf_ntohl(ip->daddr);
        u16 src_port = 0;
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
        if (src_ip == htonl(0x0AF40004) && (dst_ip == serverPod0IP || dst_ip == serverPod1IP || dst_ip == serverPod2IP)) {
            u32 time_key = 0;
            u64 *last_time = time_map.lookup(&time_key);
            u64 now = bpf_ktime_get_ns();
            u32 limit_rate_key = 0;
            u32 token_rate_key = 0;
            u32 per_sec_rate_key = 0;
            u32 *limit_rate_v = limit_rate.lookup(&limit_rate_key);
            u32 *token_rate_v = token_rate.lookup(&token_rate_key);
            u32 *per_sec_rate_v = per_sec_rate.lookup(&per_sec_rate_key);
            if (last_time == NULL) {
                time_map.update(&time_key, &now);
                return XDP_PASS;
            }
            if ((last_time) && (limit_rate_v) && (token_rate_v) && (per_sec_rate_v)) {
                if ((int)(*limit_rate_v) > 1 &&  (int)(*token_rate_v) + (int)((*per_sec_rate_v) * (now - (*last_time) ) / 1000000000 ) > 1) {
                    (*token_rate_v) = (*token_rate_v) - 500;
                    token_rate.update(&token_rate_key, token_rate_v);
                    time_map.update(&time_key, &now);
                    bpf_trace_printk("Pass\\n");
                    return XDP_PASS;
                } else {
                    bpf_trace_printk("Drop\\n");
                    time_map.update(&time_key, &now);
                    return XDP_DROP;
                }
            }
            
        }
    }
    
    return XDP_PASS;  // Allow other packets to pass.
}
"""

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


# Initialize BPF object
b = BPF(text=bpf_code)
prob = b["limit_rate"]
prob[ctypes.c_uint(0)] = ctypes.c_uint(1000)
prob = b["token_rate"]
prob[ctypes.c_uint(0)] = ctypes.c_uint(1000)
prob = b["per_sec_rate"]
prob[ctypes.c_uint(0)] = ctypes.c_uint(1000)

service_pod_mapping, services, pods = get_kubernetes_info()
for svc, all_pods in service_pod_mapping.items():
    service_pod_map = b[svc + "_pod"]
    for i in range(len(all_pods)):
        for pod in pods.items:
            if all_pods[i] == pod.metadata.name:
                service_pod_map[ctypes.c_uint32(i)] = ctypes.c_uint32(ip_to_hex(pod.status.pod_ip))
                break

# Attach the eBPF program to the network interface (e.g., eth0)
interface = "cni0"  # Modify with the interface you want to attach the program to
b.attach_xdp(interface, b.load_func("drop_packet", bcc.BPF.XDP))

print(f"eBPF program attached to {interface}. Dropping packets from 10.244.0.4...")

# Start tracing dropped packets
try:
    while True:
        # Print the output from bpf_printk
        b.trace_print()
        # # Get reference to the hash map
        # time_stamp_map = b["time_stamp"]

        # # Iterate through all entries in the map
        # print("Current entries in time_stamp map:")
        # for key, value in time_stamp_map.items():
        #     ip = key.ip
        #     port = key.port
        #     timestamp = value.value  # value is a ctypes type, so use `.value`
            
        #     print(f"IP: {ip}, Port: {port}, Timestamp: {timestamp}")
        # time.sleep(10)
except KeyboardInterrupt:
    print("Detaching eBPF program")
    # Detach the program when done
    b.remove_xdp(interface)
