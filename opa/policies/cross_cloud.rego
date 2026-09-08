package zta.crosscloud

import future.keywords.if
import future.keywords.in

default allow = false

source_principal      := object.get(input.attributes.source, "principal", "")
destination_principal := object.get(input.attributes.destination, "principal", "")
method                 := input.attributes.request.http.method
path                   := input.attributes.request.http.path
headers                := object.get(input.attributes.request.http, "headers", {})

# Ma trận phân quyền — T-3.2: sinh từ policy/service-graph.yaml (nguồn sự
# thật duy nhất, dùng chung với zta_policy.rego) — xem
# opa/policies/service_acl.rego (generated) + scripts/gen-rego-acl.py. Không
# định nghĩa tay ở đây nữa, tránh lệch giữa 2 file như trước T-3.2.
#
# Lịch sử: trước đây có một rule "OpenStack-internal: bất kỳ workload OS nào
# gọi bất kỳ workload OS nào khác (trừ /admin)" — SỐNG THẬT trên cluster
# OpenStack (opa-config.yaml của os-security.yaml trỏ path này). Thay bằng
# ma trận cụ thể ở T-1.1 (KET-QUA-KIEM-TRA.md, đính chính T-0.6).
service_acl := data.zta.generated.service_acl

allowed_by_acl if {
  allowed_paths := service_acl[source_principal][destination_principal][method]
  some p in allowed_paths
  startswith(path, p)
}

# /transactions/execute là tiền thật — gate thêm bằng fraud-gate VÀ posture.
# Trước đây rule này (duy nhất áp cho path thật) chỉ kiểm posture_compliant,
# KHÔNG kiểm fraud_gate_valid như zta_policy.rego có làm cho path tương ứng
# — lệch giữa 2 PDP. core-banking (services/core-banking/main.py:58-92) có
# tự kiểm HMAC fraud-gate độc lập nên không phải lỗ hổng khai thác được,
# nhưng PDP nên chặn trước khi tới app (defense-in-depth) — thêm lại đây.
allow if {
  allowed_by_acl
  method == "POST"
  path == "/transactions/execute"
  fraud_gate_valid
  posture_compliant
  device_trust_compliant
}

allow if {
  allowed_by_acl
  method in ["GET", "POST"]
  path != "/transactions/execute"
}

fraud_gate_valid if {
  headers["x-fraud-gate"] == "passed"
  to_number(headers["x-fraud-score"]) < 75
}

# Additive: caller not yet updated to send the header (any other internal
# hop) is unaffected — only an explicit "non-compliant" value denies.
posture_compliant if {
  not headers["x-device-posture"]
}

posture_compliant if {
  headers["x-device-posture"] == "compliant"
}

# T-4.1: device_trust (thiết bị/trình duyệt NGƯỜI DÙNG CUỐI đăng nhập, khác
# posture_compliant ở trên là posture của chính WORKLOAD gọi). Trước đây
# device_trust chỉ cộng điểm rủi ro trong fraud-detection, không bao giờ tới
# PDP — payment-service giờ relay qua header X-Device-Trust (cùng pattern
# X-Device-Posture). Additive giống posture_compliant: caller không gửi
# header (chưa cập nhật) thì coi như không áp dụng, không phá traffic khác —
# chỉ "suspicious" (User-Agent rỗng/bot, xem web-portal/main.py) mới bị chặn
# hẳn ở đây; "new_device"/"unknown" vẫn qua PDP, chỉ cộng điểm rủi ro ở
# fraud-detection (chưa đủ căn cứ để chặn cứng một thiết bị CHỈ VÌ mới thấy
# lần đầu — xem T-4.2 cho hướng step-up thay vì chặn cứng).
device_trust_compliant if {
  not headers["x-device-trust"]
}

device_trust_compliant if {
  headers["x-device-trust"] != "suspicious"
}
