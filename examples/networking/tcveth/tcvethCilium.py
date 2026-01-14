from bcc import BPF
import argparse
import ipaddress
from pyroute2 import IPRoute
import pyroute2
import json
import os


# convert ipv4 to hexadecimal, to pass later to bpf program
def ipv4_to_hex(ip: str) -> str:
    value = int(ipaddress.IPv4Address(ip))
    return f"0x{value:08X}"

#apply configuration, if specified in the --config flag (which is passed as first arg)
def apply_config(path: str,
                 interfaces: list,
                 src_ip: str,
                 svcip: str,
                 new_dst_ip: str,
                 new_dst_ip2: str):
    if not path:
        return interfaces, src_ip, svcip, new_dst_ip, new_dst_ip2

    with open(path, "r") as f:
        cfg = json.load(f)

    if isinstance(cfg.get("interfaces"), list) and cfg["interfaces"]:
        interfaces = cfg["interfaces"]

    if isinstance(cfg.get("src_ip"), str) and cfg["src_ip"]:
        src_ip = cfg["src_ip"]

    if isinstance(cfg.get("svcip"), str) and cfg["svcip"]:
        svcip = cfg["svcip"]

    dst_list = cfg.get("dst_ip")
    if isinstance(dst_list, list) and len(dst_list) == 2:
        new_dst_ip = dst_list[0]
        new_dst_ip2 = dst_list[1]

    return interfaces, src_ip, svcip, new_dst_ip, new_dst_ip2

def cleanup():
    print("\n[*] Detaching TC and cleaning up...")

    try:
        # 删除 ingress filters（两个 parent）
        for idx in indexes:
            ipr.tc("del-filter", "bpf", idx, ":1", parent="ffff:fff2")
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
        for idx in indexes:
            ipr.tc("del", "clsact", idx)
    except Exception:
        pass


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

# if a config file is provided, ignore the upper variables and inject the new ones. Else, the variables wont change.
parser = argparse.ArgumentParser()
parser.add_argument("--config", "-c", help="Path to JSON config file", default=None)
args = parser.parse_args()

interfaces, src_ip, svcip, new_dst_ip, new_dst_ip2 = apply_config(
    args.config, interfaces, src_ip, svcip, new_dst_ip, new_dst_ip2
)
interfaces = list(dict.fromkeys(interfaces))

indexes = []
#inject configuration parameters as cflags in bpf program
cflags = [
    f"-DSRC_IP={ipv4_to_hex(src_ip)}",
    f"-DSVCIP={ipv4_to_hex(svcip)}",
    f"-DNEW_DST_IP={ipv4_to_hex(new_dst_ip)}",
    f"-DNEW_DST_IP2={ipv4_to_hex(new_dst_ip2)}",
]

# Ensure the interface exists
try:
    for ifname in interfaces:
        indexes.append(ipr.link_lookup(ifname=ifname)[0])
except IndexError:
   print(f"Error: Interface {interfaces} not found. Is it created?")
   exit(1)

# Ensure clsact qdisc is added only once
try:
    for idx in indexes:
        ipr.tc("add", "clsact", idx)
  
except Exception as e:
    print(f"clsact qdisc already exists: {e}")

# Attach to veth0 using TC
try:

    # enabled calling the script from outside directory
    here = os.path.dirname(os.path.abspath(__file__))
    c_file = os.path.join(here, "tcveth.c")
    b = BPF(src_file = c_file, cflags=cflags, debug=0)
    # TODO: Add automatically later
   # backend_set = b["backend_set"]
   # backend_set[backend_set.Key(0x0A000132)] = backend_set.Leaf(1)  # 10.0.1.110
   # backend_set[backend_set.Key(0x0A00012A)] = backend_set.Leaf(1)  # 10.0.1.42

    for idx in indexes:
        fn = b.load_func("redirect_service", BPF.SCHED_CLS)
        ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", classid=1)


    print(f"BPF attached to {interfaces} - SCHED_CLS: OK")
    print("Waiting for packets... Press Ctrl+C to stop.")
    b.trace_print()
finally:
   cleanup()
