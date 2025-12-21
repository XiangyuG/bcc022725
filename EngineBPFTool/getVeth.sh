#!/usr/bin/env bash

printf "%-30s %-20s\n" "POD" "HOST_VETH"
echo "-----------------------------------------------"

# 只取 default namespace 的 pod 名字
kubectl get pods -n default --no-headers -o custom-columns="POD:.metadata.name" | \
while read pod; do
    # 找 pod 内的第一个非 lo 接口
    iface=$(kubectl exec -n default "$pod" -- sh -c \
        "ls /sys/class/net | grep -v lo | head -n1" 2>/dev/null)

    # 有些 pod（极少数）可能 exec 失败，直接跳过
    [[ -z "$iface" ]] && continue

    # 读取 iflink
    iflink=$(kubectl exec -n default "$pod" -- \
        cat /sys/class/net/$iface/iflink 2>/dev/null)

    [[ -z "$iflink" ]] && continue

    # 在 host 上根据 ifindex 找 veth
    host_veth=$(ip -o link | awk -F': ' -v idx="$iflink" '$1 == idx {print $2}' | cut -d'@' -f1)

    printf "%-30s %-20s\n" "$pod" "$host_veth"
done