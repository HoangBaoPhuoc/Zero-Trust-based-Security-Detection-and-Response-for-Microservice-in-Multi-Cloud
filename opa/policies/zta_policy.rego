package zta.authz

import future.keywords.if
import future.keywords.in

default allow = false

headers          := input.attributes.request.http.headers
method           := input.attributes.request.http.method
path             := input.attributes.request.http.path
source_principal := object.get(
  object.get(input.attributes, "source", {}), "principal",
  object.get(object.get(input, "source", {}), "principal", ""))
destination_principal := object.get(
  object.get(input.attributes, "destination", {}), "principal",
  object.get(object.get(input, "destination", {}), "principal", ""))

# Trước đây OPA dùng io.jwt.decode() (KHÔNG kiểm chữ ký), dựa hoàn toàn vào
# api-gateway (python-jose) đã verify trước — PDP tin tuyệt đối một PEP khác
# thì thủng ngay khi đổi topology, thêm entry point, hoặc PeerAuthentication
# bị nới lỏng (xác nhận lỗ hổng thật 2026-09-05: JWT chữ ký rác + đúng issuer
# vẫn được OPA allow=true khi hỏi thẳng REST API — xem KET-QUA-KIEM-TRA.md
# T-1.2). Giờ OPA tự verify bằng io.jwt.decode_verify với JWKS thật của
# Keycloak — không còn phụ thuộc PEP khác cho việc này nữa.

bearer_token := t if {
  raw := headers["authorization"]
  startswith(raw, "Bearer ")
  t := substring(raw, 7, -1)
}

# Cùng cơ chế cache với discovery_response bên dưới (300s) — tránh round-trip
# Keycloak mỗi request. Keycloak trả về một JWK Set (nhiều key, chọn theo
# "kid" trong header JWT) — io.jwt.decode_verify hỗ trợ thẳng JWK Set JSON
# làm "cert", không cần tách riêng từng key.
jwks_response := http.send({
  "method": "GET",
  "url": "http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/openid-connect/certs",
  "force_cache": true,
  "force_cache_duration_seconds": 300,
  "raise_error": false,
})

# Không có fallback key cứng (khác với expected_issuer bên dưới) — JWKS
# không lấy được thì fail-closed đúng nguyên tắc zero-trust, không có cách
# nào an toàn để "đoán" public key khi Keycloak/mạng lỗi.
#
# BUG NGHIÊM TRỌNG đã sửa (phát hiện 2026-09-05/06, xem KET-QUA-KIEM-TRA.md
# §T-4.2 "phát hiện phụ"): io.jwt.decode_verify() của OPA (bản đã ghim ở
# T-0.5) trả về [false,{},{}] — TỪ CHỐI MỌI TOKEN, kể cả chữ ký đúng 100% —
# bất cứ khi nào token có claim "aud" mà constraints KHÔNG khai báo "aud" để
# đối chiếu. Xác nhận bằng bisect thủ công (thêm/bớt từng claim của token tự
# ký, độc lập hoàn toàn với Keycloak): chỉ riêng việc CÓ mặt "aud" (bất kể
# string hay mảng) mà thiếu constraint "aud" đã đủ làm decode_verify luôn
# fail — không liên quan gì tới chữ ký/khoá/issuer. MỌI token Keycloak thật
# đều có "aud" (mặc định hoặc do T-1.4 mapper thêm) nên bug này khiến
# jwt_signature_valid CHƯA BAO GIỜ true cho bất kỳ request thật nào kể từ khi
# đoạn code này được viết ở T-1.2 — chỉ không bị phát hiện vì traffic thật
# luôn được `internal_service_request` (T-1.1/T-3.1) cho qua trước, không
# đụng nhánh này. Thêm "aud": "api-gateway" vào constraints là đủ để sửa
# (xác nhận decode_verify tự so khớp đúng với CẢ token có "aud" dạng mảng).
jwt_verify_result := io.jwt.decode_verify(bearer_token, {
  "cert": jwks_response.raw_body,
  "iss": expected_issuer,
  "aud": "api-gateway",
}) if {
  not jwks_response.error
  jwks_response.status_code == 200
}

jwt_signature_valid if {
  jwt_verify_result[0] == true
}

jwt_payload := jwt_verify_result[2] if {
  jwt_signature_valid
}

# Issuer trước đây hardcode 1 chuỗi cố định tại đây, PHẢI khớp tuyệt đối với
# cấu hình Keycloak thật (KC_HOSTNAME/KC_HOSTNAME_PORT) và với JWT_ISSUER của
# api-gateway ở một file khác — 3 nơi độc lập cùng phải đồng bộ tay. Lệch 1
# ký tự (đã xảy ra ngày 2026-08-13, thiếu KC_HOSTNAME_PORT) làm toàn bộ JWT
# bị OPA từ chối. Giờ tự hỏi OIDC discovery document — nguồn sự thật do
# chính Keycloak công bố — cache 5 phút để không tốn round-trip mỗi request.
discovery_response := http.send({
  "method": "GET",
  "url": "http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/.well-known/openid-configuration",
  "force_cache": true,
  "force_cache_duration_seconds": 300,
  "raise_error": false,
})

# Fallback nếu discovery lỗi (Keycloak chưa lên, mạng lỗi...) — không để
# toàn bộ policy sập theo kiểu fail-closed tệ hơn cả lỗi cũ.
default expected_issuer := "http://keycloak.ztlab.local:8180/realms/ztlab"

expected_issuer := discovery_response.body.issuer if {
  not discovery_response.error
  discovery_response.status_code == 200
  discovery_response.body.issuer
}

valid_jwt if {
  jwt_signature_valid
  jwt_payload.iss == expected_issuer
  jwt_payload.exp > time.now_ns() / 1000000000
  jwt_audience_valid
}

# T-1.4: trước đây không kiểm — token phát cho client bất kỳ trong realm
# ztlab (kể cả không liên quan tới API tài chính) đều được OPA chấp nhận
# miễn issuer/exp đúng. Giờ khớp Audience mapper thêm vào client
# "web-portal"/"api-gateway". Keycloak serialize "aud" thành string đơn nếu
# chỉ có 1 audience, thành mảng nếu nhiều hơn — chấp nhận cả 2 dạng.
#
# LƯU Ý PHẠM VI THẬT (phát hiện 2026-09-05, xem KET-QUA-KIEM-TRA.md "Phát hiện
# phụ"): giá trị này chỉ được `external_api_request` dùng tới, và nhánh đó chỉ
# xét tới khi `not valid_svid` — tức caller KHÔNG có SPIFFE ID hợp lệ trong
# mesh (không có client cert, ví dụ một client thật sự ở ngoài mesh gọi vào
# qua PERMISSIVE mTLS). Với hop `web-portal -> api-gateway` hiện tại, caller
# LUÔN có SPIFFE ID hợp lệ (web-portal nằm trong mesh) nên request đã được
# cho phép qua `internal_service_request` (service_acl theo danh tính
# workload, T-1.1) TRƯỚC KHI giá trị `jwt_audience_valid` này được xét tới —
# audience của JWT người dùng cuối cho hop này do MỘT MÌNH tầng app
# (`api-gateway/main.py::_verify_token`) chịu trách nhiệm, không phải "phòng
# thủ 2 lớp" như cách viết cũ ngụ ý. Rule này vẫn đúng và nên giữ — nó là lớp
# bảo vệ thật cho một client ngoài-mesh gọi thẳng vào api-gateway (khi/nếu hệ
# thống có NodePort/ingress lộ ra ngoài, hiện repo NÀY chưa có) — chỉ là
# không nên hiểu nhầm nó đang bảo vệ hop web-portal->api-gateway hiện tại.
jwt_audience_valid if {
  jwt_payload.aud == "api-gateway"
}

jwt_audience_valid if {
  is_array(jwt_payload.aud)
  "api-gateway" in jwt_payload.aud
}

permissions := {
  "financial-read":   {"GET": true, "OPTIONS": true},
  "financial-write":  {"GET": true, "OPTIONS": true, "POST": true, "PUT": true},
  "security-analyst": {"GET": true, "OPTIONS": true},
  "security-admin":   {"GET": true, "OPTIONS": true, "POST": true, "PUT": true, "DELETE": true},
}

role_permits_action if {
  some role in jwt_payload.realm_access.roles
  permissions[role][method]
}

allow if { public_path }
allow if { external_api_request }
allow if { internal_service_request }
allow if { core_transaction_with_fraud_gate }

# T-4.2: bug io.jwt.decode_verify (thiếu constraint "aud" khi token có claim
# "aud" khiến verify luôn fail — xem comment ở jwt_verify_result phía trên)
# ĐÃ SỬA 2026-09-06. `payment_with_step_up` giờ hoạt động đúng thật —
# jwt_payload.acr đọc được, xác nhận qua traffic thật (KET-QUA-KIEM-TRA.md
# §T-4.2). Enforcement giờ có ở CẢ 2 tầng: OPA (đây — bảo vệ đúng hop
# web-portal->api-gateway) VÀ app (api-gateway/main.py::create_payment,
# giữ nguyên làm lớp thứ 2 — không gỡ, vì OPA chỉ bảo vệ hop CÓ SPIFFE ID
# đi qua sidecar, xem T-3.1 về giới hạn NetworkPolicy/port-forward tương tự
# có thể áp dụng cho đường vào không qua mesh trong tương lai).
allow if { payment_with_step_up }

public_path if { path in ["/health", "/ready", "/metrics"] }
public_path if { startswith(path, "/metrics") }
# T-4.2: OPA tự gọi lại api-gateway để đọc luỹ kế ngày (http.send, không có
# JWT/SVID nào đính kèm — opa-server không phải mesh member) — không có gì
# nhạy cảm ở đây (chỉ trả về 1 số tổng), cùng cách xử lý /health/.../metrics.
public_path if { path == "/internal/daily-cumulative" }

external_api_request if {
  method == "POST"
  path == "/payments"
  valid_jwt
  role_permits_action
  not valid_svid
}

external_api_request if {
  method == "POST"
  path == "/accounts"
  valid_jwt
  role_permits_action
  not valid_svid
}

external_api_request if {
  method in ["GET", "OPTIONS"]
  valid_jwt
  role_permits_action
  not valid_svid
}

# Ma trận phân quyền service-to-service — T-3.2: sinh từ
# policy/service-graph.yaml (nguồn sự thật duy nhất, dùng chung với
# cross_cloud.rego), KHÔNG định nghĩa tay ở đây nữa — xem
# opa/policies/service_acl.rego (generated) + scripts/gen-rego-acl.py.
# Lịch sử: trước đây `internal_service_request` chỉ kiểm `valid_svid` (bất
# kỳ SPIFFE ID hợp lệ nào trong trust domain) — nghĩa là mọi workload gọi
# được mọi workload khác miễn có SVID hợp lệ (T-1.1, KET-QUA-KIEM-TRA.md).
service_acl := data.zta.generated.service_acl

allowed_by_acl if {
  allowed_paths := service_acl[source_principal][destination_principal][method]
  some p in allowed_paths
  startswith(path, p)
}

internal_service_request if {
  valid_svid
  allowed_by_acl
  not startswith(path, "/transactions/execute")
  not sensitive_payment_request
}

core_transaction_with_fraud_gate if {
  valid_svid
  allowed_by_acl
  method == "POST"
  startswith(path, "/transactions/execute")
  fraud_gate_valid
  posture_compliant
}

# T-4.2: /payments (web-portal -> api-gateway) là điểm tiền thật đầu tiên rời
# tài khoản. Hop này được `internal_service_request` cho qua theo danh tính
# workload (đúng, T-1.1) — KHÔNG dựa vào JWT — nên phải gate riêng ở đây
# giống hệt cách `core_transaction_with_fraud_gate` gate `/transactions/execute`
# thêm ngoài `internal_service_request`, nếu không JWT của người dùng cuối
# (bao gồm `acr`) sẽ không bao giờ được PDP xét tới cho hop này (đúng loại
# khoảng trống đã phát hiện ở T-3.1 "phát hiện phụ" cho jwt_audience_valid).
sensitive_payment_request if {
  method == "POST"
  path == "/payments"
}

payment_with_step_up if {
  valid_svid
  allowed_by_acl
  sensitive_payment_request
  not requires_step_up
}

payment_with_step_up if {
  valid_svid
  allowed_by_acl
  sensitive_payment_request
  requires_step_up
  step_up_satisfied
}

# Ngưỡng theo QĐ 2345/QĐ-NHNN, TT 50/2024/TT-NHNN: xác thực mạnh khi giao
# dịch >10 triệu/lần HOẶC luỹ kế >20 triệu/ngày. Trước T-4.2, ngưỡng chặn cứng
# thật của hệ thống (CRITICAL_AMOUNT_VND/MAX_SINGLE_TXN_VND) ở mức trăm
# triệu — cao hơn 50 lần so với ngưỡng cần step-up thật, và không có step-up
# ở bất kỳ đâu.
STEP_UP_SINGLE_VND := 10000000
STEP_UP_DAILY_VND := 20000000

# Envoy KHÔNG gửi body cho ext_authz theo mặc định — istio-operator.yaml đã
# bật includeRequestBodyInCheck cho provider opa-ext-authz (2026-09-05) để
# input.attributes.request.http.body có nội dung JSON thật của /payments.
request_body := json.unmarshal(input.attributes.request.http.body) if {
  sensitive_payment_request
  input.attributes.request.http.body != ""
}

txn_amount := to_number(request_body.amount) if {
  sensitive_payment_request
}

# Số dư luỹ kế TRƯỚC giao dịch đang xét — api-gateway tự cộng dồn vào Redis
# SAU KHI mỗi giao dịch thành công (services/api-gateway/main.py), nên số
# đọc ở đây không bao giờ tính hai lần giao dịch hiện tại.
daily_cumulative_response := http.send({
  "method": "GET",
  "url": sprintf("http://api-gateway.financial.svc.cluster.local:8080/internal/daily-cumulative?account=%s", [request_body.from_account]),
  "raise_error": false,
}) if {
  sensitive_payment_request
  request_body.from_account
}

daily_cumulative_before := to_number(daily_cumulative_response.body.cumulative) if {
  not daily_cumulative_response.error
  daily_cumulative_response.status_code == 200
}

default daily_cumulative_before := 0

requires_step_up if {
  txn_amount > STEP_UP_SINGLE_VND
}

requires_step_up if {
  (daily_cumulative_before + txn_amount) > STEP_UP_DAILY_VND
}

# acr="high" chỉ đạt được sau khi người dùng hoàn thành step-up OTP qua
# Keycloak (Conditional OTP execution, gate theo Level of Authentication —
# xem k8s/keycloak/realm-config.json, client web-portal acr.loa.map).
step_up_satisfied if {
  jwt_payload.acr == "high"
}

valid_svid if {
  startswith(source_principal, "spiffe://ztlab.local/")
}

fraud_gate_valid if {
  headers["x-fraud-gate"] == "passed"
  to_number(headers["x-fraud-score"]) < 75
}

# Device/workload posture (T5 — insider với credential hợp lệ nhưng posture fail).
# Cập nhật 2026-08-23: payment-service giờ tự tính posture thật (in-process,
# shared/posture.py, không gọi mạng) và gắn header X-Device-Posture thật khi
# gọi core-banking /transactions/execute — hoàn thiện phần còn thiếu của kế
# hoạch cũ (trước đó chỉ có rule Rego + test cô lập, chưa có nguồn tín hiệu
# thật). Chuẩn "compliant" cố ý lỏng hơn "phải chạy non-root": kiểm tra thật
# ngày 2026-08-23 cho thấy MỌI service ở đây đều chạy uid=0, đọc được
# /etc/shadow, không có securityContext nào — đúng dấu hiệu "vi phạm" mà
# k8s/financial/security-scanner-job.yaml dùng để giả lập KB6. Enforce đúng
# chuẩn đó sẽ chặn luôn mọi giao dịch thật hiện tại. Nên compliant chỉ fail
# khi có dấu hiệu thật sự nguy hiểm: capability vượt quá tập mặc định của
# Docker (SYS_ADMIN/SYS_PTRACE/NET_ADMIN/SYS_MODULE/ALL) hoặc image không ghim
# tag (`:latest`/không tag) — khớp đúng chuẩn k8s/financial/posture-agent-
# cronjob.yaml dùng để audit định kỳ toàn bộ pod trong namespace.
# Vẫn giữ thiết kế cộng thêm: nếu caller không gửi header (service cũ/khác
# chưa cập nhật) thì coi như không áp dụng, cho qua — không phá traffic khác.
# tests/grafana_kb_t5_noncompliant_device.sh vẫn giả lập trực tiếp giá trị
# "non-compliant" qua REST API của OPA để kiểm chứng nhánh deny độc lập với
# payment-service thật.
posture_compliant if {
  not headers["x-device-posture"]
}

posture_compliant if {
  headers["x-device-posture"] == "compliant"
}

audit_log := {
  "timestamp":         time.now_ns(),
  "action":            method,
  "resource":          path,
  "decision":          allow,
  "svid":              source_principal,
  "device_posture":    object.get(headers, "x-device-posture", "not_reported"),
}
