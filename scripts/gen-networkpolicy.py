#!/usr/bin/env python3
"""Sinh NetworkPolicy pod-level (L4) từ policy/service-graph.yaml (T-3.2).

Sinh 2 file:
  k8s/financial/network-policies/aws-pod-segmentation.yaml   (edge cluster=aws)
  k8s/financial/network-policies/os-pod-segmentation.yaml    (edge cluster=openstack)

Mỗi NetworkPolicy chỉ siết chiều INGRESS của một workload đích cụ thể, gộp
tất cả nguồn được phép gọi tới nó (từ mọi edge có `to` trỏ vào workload đó
trong cùng cluster). Bỏ qua edge `cross_cluster: true` — cơ chế cross-cloud
dùng ipBlock (NodePort qua WireGuard), khai báo riêng trong
aws-allow-list.yaml/os-allow-list.yaml, không phải podSelector.

LƯU Ý (T-3.1, KET-QUA-KIEM-TRA.md): NetworkPolicy sinh ra đây hiện KHÔNG
được kube-router enforce cho traffic đi qua Istio sidecar trên hạ tầng đang
dùng. Vẫn sinh đúng theo ý định/khai báo — giá trị tài liệu hoá + sẵn sàng
nếu hạ tầng CNI thay đổi.

Usage: python3 scripts/gen-networkpolicy.py
Nghiệm thu: `git diff k8s/financial/network-policies/{aws,os}-pod-segmentation.yaml`
rỗng nếu service-graph.yaml không đổi.
"""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_FILE = REPO_ROOT / "policy" / "service-graph.yaml"
NETPOL_DIR = REPO_ROOT / "k8s" / "financial" / "network-policies"

HEADER = """# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph.yaml
# Sinh lại: python3 scripts/gen-networkpolicy.py
#
# T-3.1/T-3.2 — mỗi NetworkPolicy chỉ siết chiều INGRESS của một workload
# đích, khớp đúng traffic thật đã đo (T-1.1). Egress không đổi (xem
# {allow_list_file}). LƯU Ý: NetworkPolicy này hiện KHÔNG được kube-router
# enforce cho traffic có Istio sidecar trên hạ tầng đang dùng — xem
# KET-QUA-KIEM-TRA.md §T-3.1 trước khi coi đây là lớp bảo vệ đang hoạt động.
"""


def app_label(graph: dict, workload: str) -> str:
    w = graph["workloads"][workload]
    return w.get("app_label") or w.get("service_account") or workload.split("/")[-1]


def render_policy(name: str, dest_label: str, sources: list[tuple[str, list[int]]]) -> str:
    # Gộp theo (source, ports) — mỗi source có thể xuất hiện ở nhiều edge
    # (không xảy ra trong graph hiện tại nhưng generator vẫn xử lý đúng nếu có).
    from_blocks = []
    for src_label, ports in sources:
        from_blocks.append(
            f"""    - from:
        - podSelector:
            matchLabels:
              app: {src_label}
      ports:
{render_ports(ports)}"""
        )
    ingress = "\n".join(from_blocks)
    return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}
  namespace: financial
spec:
  podSelector:
    matchLabels:
      app: {dest_label}
  policyTypes:
    - Ingress
  ingress:
{ingress}
"""


def render_ports(ports: list[int]) -> str:
    lines = []
    for p in ports:
        lines.append(f"        - port: {p}")
        lines.append("          protocol: TCP")
    return "\n".join(lines)


def gen_for_cluster(graph: dict, cluster: str, prefix: str, allow_list_file: str) -> str:
    by_dest: dict[str, list[tuple[str, list[int]]]] = {}
    for edge in graph["edges"]:
        if edge.get("cross_cluster"):
            continue
        src_workload = graph["workloads"].get(edge["from"])
        dst_workload = graph["workloads"].get(edge["to"])
        if not src_workload or not dst_workload:
            continue
        if src_workload["cluster"] != cluster or dst_workload["cluster"] != cluster:
            continue
        ports = edge.get("l4_ports")
        if not ports:
            continue
        by_dest.setdefault(edge["to"], []).append((app_label(graph, edge["from"]), ports))

    policies = [HEADER.format(allow_list_file=allow_list_file)]
    for dest in sorted(by_dest):
        dest_label = app_label(graph, dest)
        policy_name = f"{prefix}-pod-{dest_label}"
        policies.append(render_policy(policy_name, dest_label, by_dest[dest]))
    return "---\n".join(policies)


def main() -> None:
    graph = yaml.safe_load(GRAPH_FILE.read_text())

    aws_content = gen_for_cluster(graph, "aws", "aws", "aws-allow-list.yaml")
    os_content = gen_for_cluster(graph, "openstack", "os", "os-allow-list.yaml")

    (NETPOL_DIR / "aws-pod-segmentation.yaml").write_text(aws_content)
    (NETPOL_DIR / "os-pod-segmentation.yaml").write_text(os_content)
    print(f"Sinh xong: {NETPOL_DIR.relative_to(REPO_ROOT)}/{{aws,os}}-pod-segmentation.yaml")


if __name__ == "__main__":
    main()
