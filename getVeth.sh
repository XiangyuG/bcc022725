#!/usr/bin/env bash

printf "%-30s %-20s %-15s %-12s\n" "POD" "HOST_VETH" "IP" "IP_HEX"
echo "----------------------------------------------------------------------------"

kubectl get pods -n default --no-headers -o custom-columns="POD:.metadata.name" | \
while read pod; do
    # 找 pod 内的第一个非 lo 接口
    iface=$(kubectl exec -n default "$pod" -- sh -c \
        "ls /sys/class/net | grep -v lo | head -n1" 2>/dev/null)

    [[ -z "$iface" ]] && continue

    # 读取 iflink
    iflink=$(kubectl exec -n default "$pod" -- \
        cat /sys/class/net/$iface/iflink 2>/dev/null)

    [[ -z "$iflink" ]] && continue

    # 在 host 上根据 ifindex 找 veth
    host_veth=$(ip -o link | awk -F': ' -v idx="$iflink" '$1 == idx {print $2}' | cut -d'@' -f1)

    [[ -z "$host_veth" ]] && continue

    # 读取 Pod IP（直接从 k8s API，最稳）
    pod_ip=$(kubectl get pod -n default "$pod" -o jsonpath='{.status.podIP}' 2>/dev/null)

    [[ -z "$pod_ip" ]] && continue

    # IP -> hex（网络字节序）
    ip_hex=$(printf '%02X%02X%02X%02X\n' ${pod_ip//./ })

    printf "%-30s %-20s %-15s 0x%-10s\n" "$pod" "$host_veth" "$pod_ip" "$ip_hex"
done

