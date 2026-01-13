from bcc import BPF
from pyroute2 import IPRoute
import pyroute2

from kube_query import *

def ipv4_to_hex(ip: str) -> str:
    value = int(ipaddress.IPv4Address(ip))
    return f"0x{value:08X}"

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

interfaces = [
 "lxcb54b62d61434",
 "lxc102115b89e79",
 "lxc04e01eda2318",
]

src_ip     = "10.0.1.210"
svcip      = "10.104.111.207"
new_dst_ip = "10.0.1.122"
new_dst_ip2= "10.0.1.84"

cflags = [
    f"-DSRC_IP={ipv4_to_hex(src_ip)}",
    f"-DSVCIP={ipv4_to_hex(svcip)}",
    f"-DNEW_DST_IP={ipv4_to_hex(new_dst_ip)}",
    f"-DNEW_DST_IP2={ipv4_to_hex(new_dst_ip2)}",
]

# Ensure the interface exists
try:
    interfaces = list(dict.fromkeys(interfaces))
    for ifname in interfaces.items():
        ipr.link_lookup(ifname=ifname)[0]
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
    b = BPF(src_file = "tcveth.c", cflags=cflags, debug=0)
    service_pod_mapping, services, pods = kube_query()
    # TODO: Add automatically later
   # backend_set = b["backend_set"]
   # backend_set[backend_set.Key(0x0A000132)] = backend_set.Leaf(1)  # 10.0.1.110
   # backend_set[backend_set.Key(0x0A00012A)] = backend_set.Leaf(1)  # 10.0.1.42

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
