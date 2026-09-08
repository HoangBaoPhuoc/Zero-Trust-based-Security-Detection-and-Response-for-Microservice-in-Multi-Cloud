#!/bin/bash
# T4 — Valid credentials + valid fraud-gate, but end-user device flagged "suspicious"
# Zero Trust layer: Dynamic policy (NIST SP 800-207 tenet 4) — device_trust_compliant
#                    trong opa/policies/cross_cloud.rego (đường thật của
#                    payment-service -> core-banking /transactions/execute)
#
# Khác posture_compliant (T5, kb_t5): posture_compliant là posture của chính
# WORKLOAD gọi (payment-service pod có bị chiếm/cấu hình sai không).
# device_trust_compliant là tín hiệu về THIẾT BỊ/TRÌNH DUYỆT của NGƯỜI DÙNG
# CUỐI đăng nhập qua web-portal (web-portal/main.py::_evaluate_device_trust)
# — trước T-4.1, tín hiệu này chỉ cộng điểm rủi ro bên trong fraud-detection,
# không bao giờ tới PDP.
#
# Cách kiểm thử: giống hệt pattern kb_t5 — port-forward opa-service:8181,
# POST input đúng shape Envoy ext_authz gửi tới zta/crosscloud/allow (đường
# thật của /transactions/execute), cô lập logic Rego.
#
# Attack: input có valid_svid + fraud_gate_valid hợp lệ (score=5<75,
#         gate=passed) NHƯNG x-device-trust=suspicious → kỳ vọng allow=false.
# Đối chứng: input giống hệt nhưng KHÔNG có header x-device-trust (giống toàn
#         bộ traffic thật TRƯỚC T-4.1) → kỳ vọng allow=true (additive, không
#         phá traffic cũ).
set -euo pipefail

CONTEXT="${KUBE_CONTEXT:-ctx-openstack}"
NAMESPACE="financial"
SCENARIO="T4_untrusted_device"
LOCAL_PORT=18182

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

cleanup() { [[ -n "${PF_PID:-}" ]] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

kubectl --context "$CONTEXT" port-forward -n "$NAMESPACE" svc/opa-service \
  "${LOCAL_PORT}:8181" > /tmp/ztlab-t4-opa-pf.log 2>&1 &
PF_PID=$!
for i in $(seq 1 10); do
  curl -s -o /dev/null "http://localhost:${LOCAL_PORT}/health" 2>/dev/null && break
  sleep 1
done

query_opa_crosscloud() {
  local headers_json="$1"
  curl -s -X POST "http://localhost:${LOCAL_PORT}/v1/data/zta/crosscloud/allow" \
    -H "Content-Type: application/json" \
    -d "{\"input\":{\"attributes\":{\"source\":{\"principal\":\"spiffe://ztlab.local/aws/payment-service\"},\"destination\":{\"principal\":\"spiffe://ztlab.local/openstack/core-banking\"},\"request\":{\"http\":{\"method\":\"POST\",\"path\":\"/transactions/execute\",\"headers\":${headers_json}}}}}}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('result'))" 2>/dev/null || echo "request_failed"
}

log "Đối chứng: input KHÔNG có x-device-trust (giống traffic thật trước T-4.1)"
control=$(query_opa_crosscloud '{"x-fraud-gate":"passed","x-fraud-score":"5"}')
log "  OPA allow = $control (kỳ vọng True)"
[[ "$control" == "True" ]] || fail "Đối chứng FAIL — thay đổi Rego đã phá traffic hiện có (allow phải =True khi thiếu header)"

log "Đối chứng 2: input có x-device-trust=trusted (thiết bị quen)"
trusted=$(query_opa_crosscloud '{"x-fraud-gate":"passed","x-fraud-score":"5","x-device-trust":"trusted"}')
log "  OPA allow = $trusted (kỳ vọng True)"
[[ "$trusted" == "True" ]] || fail "Đối chứng 2 FAIL — device_trust=trusted phải luôn allow=True"

log "Tấn công: input GIỐNG HỆT + x-device-trust=suspicious"
denied=0
for i in 1 2 3; do
  result=$(query_opa_crosscloud '{"x-fraud-gate":"passed","x-fraud-score":"5","x-device-trust":"suspicious"}')
  log "  Attempt $i -> OPA allow = $result"
  [[ "$result" == "False" ]] && denied=$((denied+1))
done
[[ $denied -ge 2 ]] || fail "OPA chỉ deny $denied/3 (cần >=2) — device_trust_compliant chưa hoạt động đúng"

log "→ Chứng minh: credential hợp lệ + fraud-gate hợp lệ + workload posture hợp lệ vẫn KHÔNG đủ nếu thiết bị người dùng cuối bị đánh dấu suspicious"
pass "T4 DONE | zta.crosscloud deny khi device_trust=suspicious, allow khi trusted/thiếu header — không phá traffic hiện có"
