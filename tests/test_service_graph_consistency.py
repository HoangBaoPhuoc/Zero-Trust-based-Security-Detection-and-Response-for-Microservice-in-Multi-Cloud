"""T-3.2 — kiểm tra policy/service-graph.yaml là nguồn sự thật duy nhất thật sự.

Hai bài test:
1. File sinh ra (opa/policies/service_acl.rego,
   k8s/financial/network-policies/{aws,os}-pod-segmentation.yaml) khớp
   CHÍNH XÁC với những gì generator sinh ra từ service-graph.yaml ngay lúc
   này — nếu ai đó sửa tay 1 trong 2 phía (graph hoặc file generated) mà
   quên chạy lại generator, test này FAIL. Đây là nghiệm thu chính thức của
   T-3.2 trong KE-HOACH-SUA-HE-THONG.md ("chạy generator -> git diff không
   đổi").
2. Mọi edge nghiệp vụ (không phải l4_only, không phải cross_cluster) khai
   báo trong service-graph.yaml phải xuất hiện Ở CẢ HAI file sinh ra (L7 và
   L4) — tức là không có cặp nào chỉ được khai báo ở 1 tầng mà quên tầng kia.

LƯU Ý (đọc trước khi diễn giải test #2 là "L4 thực sự chặn"): test này chỉ
xác nhận tính nhất quán giữa 2 FILE KHAI BÁO, không xác nhận enforcement
thật ở hạ tầng. T-3.1 (KET-QUA-KIEM-TRA.md) đã xác nhận NetworkPolicy sinh
ra từ đây KHÔNG được kube-router enforce cho traffic có Istio sidecar trên
hạ tầng đang dùng — L7 (OPA, service_acl.rego) mới là lớp đang chặn thật.

Chạy: python3 -m pytest tests/test_service_graph_consistency.py -v
      (hoặc: python3 tests/test_service_graph_consistency.py)
"""
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_FILE = REPO_ROOT / "policy" / "service-graph.yaml"
REGO_OUT = REPO_ROOT / "opa" / "policies" / "service_acl.rego"
NETPOL_AWS = REPO_ROOT / "k8s" / "financial" / "network-policies" / "aws-pod-segmentation.yaml"
NETPOL_OS = REPO_ROOT / "k8s" / "financial" / "network-policies" / "os-pod-segmentation.yaml"


def _run_generator(script: str) -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / script)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"{script} lỗi:\n{result.stdout}\n{result.stderr}"


def test_generated_files_match_source_of_truth():
    """Nghiệm thu chính thức T-3.2: chạy generator xong, nội dung file không đổi."""
    before = {
        REGO_OUT: REGO_OUT.read_text(),
        NETPOL_AWS: NETPOL_AWS.read_text(),
        NETPOL_OS: NETPOL_OS.read_text(),
    }

    _run_generator("gen-rego-acl.py")
    _run_generator("gen-networkpolicy.py")

    for path, old_content in before.items():
        new_content = path.read_text()
        assert new_content == old_content, (
            f"{path.relative_to(REPO_ROOT)} lệch với policy/service-graph.yaml — "
            f"ai đó sửa tay file generated hoặc quên chạy lại generator sau khi sửa graph."
        )


def _business_edges(graph: dict) -> list[dict]:
    return [
        e for e in graph["edges"]
        if not e.get("l4_only") and not e.get("cross_cluster")
    ]


def _app_label(graph: dict, workload: str) -> str:
    w = graph["workloads"][workload]
    return w.get("app_label") or w.get("service_account") or workload.split("/")[-1]


def test_every_business_edge_present_in_both_layers():
    """Mọi cặp nguồn->đích nghiệp vụ (cùng cluster) phải có mặt ở CẢ L7 (rego)
    lẫn L4 (NetworkPolicy) — không cặp nào chỉ khai báo 1 tầng rồi quên tầng kia.

    KHÔNG kiểm tra enforcement thật — chỉ kiểm tra khai báo. Xem docstring
    module này + KET-QUA-KIEM-TRA.md §T-3.1 về giới hạn enforcement L4 thật.
    """
    graph = yaml.safe_load(GRAPH_FILE.read_text())
    rego_text = REGO_OUT.read_text()
    netpol_aws = yaml.safe_load_all(NETPOL_AWS.read_text())
    netpol_os = yaml.safe_load_all(NETPOL_OS.read_text())
    netpol_docs = [d for d in list(netpol_aws) + list(netpol_os) if d]

    # L4: gom (dest podSelector app label) -> {source app labels được allow}
    l4_allowed: dict[str, set[str]] = {}
    for doc in netpol_docs:
        dest_label = doc["spec"]["podSelector"]["matchLabels"]["app"]
        sources = set()
        for rule in doc["spec"].get("ingress", []):
            for peer in rule.get("from", []):
                sel = peer.get("podSelector", {}).get("matchLabels", {})
                if "app" in sel:
                    sources.add(sel["app"])
        l4_allowed[dest_label] = sources

    missing_l4 = []
    missing_l7 = []
    for edge in _business_edges(graph):
        src_workload = graph["workloads"][edge["from"]]
        dst_workload = graph["workloads"][edge["to"]]
        if src_workload["cluster"] != dst_workload["cluster"]:
            continue  # cross-cluster đã lọc, nhưng phòng hờ dữ liệu graph sai

        dst_label = _app_label(graph, edge["to"])
        src_label = _app_label(graph, edge["from"])
        if src_label not in l4_allowed.get(dst_label, set()):
            missing_l4.append(f"{edge['from']} -> {edge['to']}")

        src_id = f'spiffe://{graph["trust_domain"]}/{edge["from"]}'
        dst_id = f'spiffe://{graph["trust_domain"]}/{edge["to"]}'
        if f'"{src_id}"' not in rego_text or f'"{dst_id}"' not in rego_text:
            missing_l7.append(f"{edge['from']} -> {edge['to']}")

    assert not missing_l4, f"Thiếu ở NetworkPolicy (L4): {missing_l4}"
    assert not missing_l7, f"Thiếu ở service_acl.rego (L7): {missing_l7}"


if __name__ == "__main__":
    test_generated_files_match_source_of_truth()
    print("test_generated_files_match_source_of_truth: PASS")
    test_every_business_edge_present_in_both_layers()
    print("test_every_business_edge_present_in_both_layers: PASS")
