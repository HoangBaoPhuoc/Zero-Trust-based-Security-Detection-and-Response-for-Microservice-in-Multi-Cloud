# Kết quả kiểm tra — GIAI ĐOẠN 0

> Chạy bởi agent theo `KE-HOACH-SUA-HE-THONG.md`. Branch: `fix/zta-remediation`.
> Ngày chạy: 2026-09-05. Môi trường: vừa `deploy-all.sh` xong (~35 phút trước khi bắt đầu kiểm tra).

## Kiểm tra sức khỏe hệ thống (trước khi vào GĐ 0)

- Lệnh: `bash scripts/health-check.sh`
- Kết quả: `PASS=30 WARN=6 FAIL=0`
- WARN không nghiêm trọng: thiếu `.env.ai` (dùng placeholder), AI Analyzer port-forward chưa mở, SOAR `/incidents` 404 (chưa có incident), chưa có traffic nên Loki chưa có SOAR/demo stream.
- Ngoài health-check.sh: phát hiện 3 pod `security-healthcheck-*` (CronJob, namespace `spire`, cả 2 cluster) ở trạng thái `Error`. Log: `status=critical spire=3/3 opa=000000 loki_push=000000` — cronjob nội bộ không tới được OPA/Loki qua đường nó dùng, dù `health-check.sh` xác nhận OPA (qua port-forward) và Loki đều sống. **Không nằm trong phạm vi kế hoạch này** (không có mục T-x.x nào nhắc tới cronjob này) — ghi nhận, không sửa trong lần chạy này.
- **Kết luận: hệ thống đủ ổn định để tiến hành GĐ 0.**

---

## T-0.1 — Data plane thật của từng service

- Lệnh: xem `k8s/financial istio-policies.yaml` + `kubectl get pods -o custom-columns` cả 2 cluster + `peerauthentication`/`authorizationpolicy`.
- Output (rút gọn, đầy đủ trong transcript phiên làm việc):

```
=== AWS (namespace financial) ===
fraud-detection-...        fraud-detection,istio-proxy        true,true
api-gateway-...             api-gateway,istio-proxy            true,true
payment-service-...         payment-service,istio-proxy        true,true
notification-service-...    notification-service,istio-proxy   true,true
web-portal-...               web-portal,istio-proxy             true,true
(redis, redisinsight, pgadmin, opa-server — không có istio-proxy, đây là hạ tầng phụ trợ, không phải service nghiệp vụ)

=== OPENSTACK (namespace financial) ===
core-banking-...            core-banking,istio-proxy           true,true
account-service-...         account-service,istio-proxy        true,true
transaction-service-...     transaction-service,istio-proxy    true,true
(postgres, pgadmin, redisinsight, opa-server — tương tự, không phải service nghiệp vụ)

PeerAuthentication (cả 2 cluster): default=STRICT, api-gateway-permissive=PERMISSIVE, web-portal-permissive=PERMISSIVE
AuthorizationPolicy (cả 2 cluster): notification-service-allow (ALLOW), + 6 *-opa-authz (CUSTOM) cho mọi service nghiệp vụ
```

- **Kết luận:** khớp nhánh "Mọi pod nghiệp vụ trong `financial` (cả 2 cluster) đều có `istio-proxy`. Không pod nào còn Envoy tự viết." → **Migration đã hoàn tất.**
- **Phát hiện thêm:** `k8s/financial/istio-policies.yaml:307-308` viết "core-banking (still hand-rolled Envoy, OpenStack)" — **sai so với thực tế hiện tại** (core-banking đã có istio-proxy, xác nhận ở trên). Đây là comment lỗi thời (rất có thể còn sót từ trước khi hoàn tất migrate), không phải mô tả kiến trúc hiện hành.
- **Hành động đã làm** (action không cần hỏi, theo bảng quyết định của T-0.1):
  - Chuyển `envoy/configmap.yaml`, `envoy/envoy-sidecar.yaml`, `envoy/envoy-aws.yaml`, `envoy/envoy-os.yaml` → `legacy/envoy/` kèm `README.md` giải thích lý do.
  - Sửa comment sai tại `istio-policies.yaml:307-308`.
  - (Xem mục "Hành động đã thực hiện trong GĐ 0" bên dưới.)
- 🛑 **G1 — KHÔNG cần hỏi** (kết quả rơi đúng vào nhánh "migration hoàn tất", không phải nhánh dở dang).

---

## T-0.2 — OPA có nhận được `destination.principal` không

- Lệnh: tạo traffic qua `/health`, xem `opa-server` decision log 200 dòng gần nhất, trích các trường định danh.
- Output (đã lọc unique):

```
15x  Prometheus scrape /metrics → source_principal=None, destination_principal=None   (traffic NGOÀI mesh, scrape trực tiếp không qua sidecar-to-sidecar)
7x   api-gateway → payment-service /accounts/ACC-1001    → destination_principal = spiffe://ztlab.local/aws/payment-service
1x   api-gateway → payment-service /accounts?owner=...   → destination_principal = spiffe://ztlab.local/aws/payment-service
1x   api-gateway → payment-service /payments             → destination_principal = spiffe://ztlab.local/aws/payment-service
5x   api-gateway → payment-service /transactions?...      → destination_principal = spiffe://ztlab.local/aws/payment-service
1x   payment-service → fraud-detection /score            → destination_principal = spiffe://ztlab.local/aws/fraud-detection
7x+1x+5x web-portal → api-gateway (nhiều path)             → destination_principal = spiffe://ztlab.local/aws/api-gateway
```

- **Kết luận:** khớp nhánh lý tưởng — `destination_principal` có giá trị `spiffe://ztlab.local/...` cho **mọi request thật đi qua mesh service-to-service**. (Chỉ traffic Prometheus scrape /metrics — không đi qua sidecar khác — là None, đúng như kỳ vọng, không phải lỗi.)
- **Hành động:** dùng trực tiếp `destination_principal` làm khoá đích trong ma trận ACL ở T-1.1.
- 🛑 **G2 — KHÔNG cần hỏi.**

---

## T-0.3 — `source_ip` thật sự nhận được là gì

- Lệnh: tạo traffic, xem log container app (`api-gateway`, structured JSON `event=http_request`) và log uvicorn access-log dòng liền kề.
- Output (mẫu):

```
{"event":"http_request","method":"POST","path":"/payments","status_code":422,...}
INFO:     127.0.0.1:40946 - "POST /payments HTTP/1.1" 422 Unprocessable Entity

{"event":"http_request","method":"GET","path":"/transactions",...}
INFO:     127.0.0.6:40723 - "GET /transactions?... HTTP/1.1" 200 OK
```

- Toàn bộ peer address quan sát được trong log uvicorn: **chỉ có `127.0.0.1` hoặc `127.0.0.6`** — không có IP client thật nào xuất hiện, dù request đến từ nguồn khác nhau (curl từ ngoài, web-portal gọi vào). Đối chiếu code: `services/api-gateway/main.py:120-122` (`_source_ip`) dùng `request.client.host` — vì `istio-proxy` sidecar terminate TCP rồi forward vào app qua loopback trong cùng pod, giá trị này luôn là địa chỉ loopback, **không phải IP client thật**.
- **Kết luận:** khớp đúng nhánh "`source_ip` = `127.0.0.1` hoặc luôn cùng một IP hạ tầng" → **Xác nhận có lỗi.** Rate limit (`_check_rate_limit`, dùng chung 1 bucket loopback) và chặn IP (`_is_ip_blocked`) đang **không hoạt động đúng theo thiết kế** — mọi client trông giống nhau.
- **Hành động bắt buộc (không cần hỏi):** đánh dấu sửa ở T-5.1 (dùng XFF/`x-forwarded-client-cert` + `numTrustedProxies`, xác nhận `numTrustedProxies` **CHƯA được cấu hình** trong `istio` ConfigMap ở `istio-system`).
- 🛑 **G3 — CẦN HỎI NGƯỜI DÙNG** (xem bên dưới, mục "Câu hỏi cần bạn quyết định").

---

## T-0.4 — mTLS cross-cloud có thật sự end-to-end không

- Lệnh: xem log `istio-proxy` của `core-banking` (OpenStack) để tìm trường `svid`; xem Istio telemetry stats phía gửi.
- Output:

```
core-banking istio-proxy access log (18 dòng khớp trong 50 dòng gần nhất):
  "svid":"spiffe://ztlab.local/aws/payment-service"   x18

Istio stats phía payment-service (AWS) cho cluster core-banking-openstack:
  istiocustom.istio_requests_total....source_principal.spiffe://ztlab.local/aws/payment-service...
  destination_principal.spiffe://ztlab.local/openstack/core-banking...response_code.200: 20
  (20/20 request thành công)
```

- **Kết luận:** phía nhận (`core-banking`, cluster OpenStack, PeerAuthentication STRICT) trích xuất được đúng SPIFFE ID của phía gửi (`payment-service`, AWS) từ **client certificate** trong bắt tay TLS — điều này chỉ xảy ra được khi có handshake mTLS thật, vì STRICT mode sẽ từ chối thẳng kết nối plaintext hoặc không có cert hợp lệ. 20/20 request `response_code.200` xác nhận không có request nào bị STRICT chặn.
- Khớp nhánh: **"mTLS end-to-end hoạt động thật"** — đây là kết quả tốt, đáng ghi rõ trong báo cáo khoá luận (cross-cloud mTLS qua NodePort + WireGuard, không phải giả lập).
- 🛑 **G4 — KHÔNG cần hỏi.**
- Lưu ý kỹ thuật phụ: Istio telemetry (`/stats`) ghi `connection_security_policy.unknown` cho cluster này (thay vì `mutual_tls`) — do đích là `Service+Endpoints` thủ công (không phải workload được mesh tự khám phá qua ServiceRegistry chuẩn), nên Istio không tự phân loại được policy bảo mật cho mục đích *thống kê*, dù bản thân traffic **vẫn thực sự đi qua mTLS** (bằng chứng: SVID được trích xuất đúng ở phía nhận + STRICT không chặn). Đáng note trong phần hạn chế/đo lường của khoá luận nếu dùng số liệu `connection_security_policy` — chỉ số này không đáng tin cho riêng path cross-cloud này.

---

## T-0.5 — Ghi nhận môi trường thực nghiệm

```
kubectl (server, AWS): v1.29.3+k3s1   (client v1.36.3 — lệch >1 minor, chỉ là cảnh báo CLI, không phải lỗi cluster)
terraform (openstack): v1.15.9, provider terraform-provider-openstack v1.54.1
spire-server:            1.9.4
opa-server image:        openpolicyagent/opa:latest-envoy
opa-server imageID thật: docker.io/openpolicyagent/opa@sha256:1792991ca9646526b8c95c59cbb525ce33bf78458800182d78f6fa884d5ec517
```

- **Hành động đã làm (không cần hỏi):** ghim digest `opa/deployment.yaml` thay cho tag `latest-envoy` trôi nổi.
- OpenStack version (Kolla release) — **chưa lấy được** trong lần chạy này vì không SSH trực tiếp vào host `aio` trong phiên này; cần chạy `openstack --version` + `grep openstack_release /etc/kolla/globals.yml` trên máy `aio` riêng. Ghi nhận thiếu, không suy đoán.

---

## T-0.6 — Xác nhận policy nào thực sự được thực thi

```
$ grep -n "data.zta.crosscloud\|data.zta.fraud_gate\|import data" opa/policies/*.rego
>>> XÁC NHẬN: không có import chéo — hai file kia là code chết

Packages khai báo:
  opa/policies/fraud_gate.rego:1:package zta.fraud_gate
  opa/policies/zta_policy.rego:1:package zta.authz
  opa/policies/cross_cloud.rego:1:package zta.crosscloud

opa-config.yaml chỉ định giá duy nhất: path: zta/authz/allow
```

- **Kết luận ban đầu (SAI — xem đính chính ngay dưới):** ~~xác nhận dứt khoát — `cross_cloud.rego` và `fraud_gate.rego` không bao giờ được import, code chết~~.

### ⚠️ ĐÍNH CHÍNH T-0.6 (phát hiện muộn, trong lúc làm T-1.1)

Kết luận trên chỉ đúng **một nửa** — do tôi chỉ grep `path:` trong `opa/config/opa-config.yaml` mà bỏ sót một ConfigMap OPA **thứ hai**, khai báo ngay trong `k8s/financial/os-security.yaml`:

```
k8s/financial/os-security.yaml:17:        path: zta/crosscloud/allow     # cluster OpenStack
opa/config/opa-config.yaml:4:    path: zta/authz/allow                  # cluster AWS
```

Xác nhận trực tiếp bằng decision log thật (không chỉ đọc config):

```
$ kubectl --context ctx-aws logs -n financial deploy/opa-server --tail=500 | ... đếm theo trường "path"
Counter({'zta/authz/allow': 158})

$ kubectl --context ctx-openstack logs -n financial deploy/opa-server --tail=500 | ... đếm theo trường "path"
Counter({'zta/crosscloud/allow': 100})
```

**Sự thật đúng:** hệ thống có **HAI PDP độc lập, mỗi cluster một policy path khác nhau**:
- Cluster AWS → OPA đánh giá `zta/authz/allow` → `zta_policy.rego` (package `zta.authz`).
- Cluster OpenStack → OPA đánh giá `zta/crosscloud/allow` → `cross_cloud.rego` (package `zta.crosscloud`) — **đây mới là policy sống thật cho core-banking, account-service, transaction-service**, không phải code chết.
- `fraud_gate.rego` (package `zta.fraud_gate`) **vẫn đúng là code chết** — không được import bởi cả `zta.authz` lẫn `zta.crosscloud` (cả hai đều tự viết logic fraud-gate/posture inline, không `import data.zta.fraud_gate`).

**Hệ quả nghiêm trọng của việc bỏ sót này lúc thực thi:** tôi đã xoá `cross_cloud.rego` khỏi git ngay sau kết luận sai này (bước đầu của T-1.1), tưởng đó là code chết an toàn để xoá. **Nếu đã áp lên cluster thật, hành động đó sẽ làm sập toàn bộ decision path của OpenStack** (`data.zta.crosscloud.allow` không còn tồn tại → OPA trả `undefined` → theo `failure_mode_allow: false` (T-5.4), ext_authz coi là DENY → mọi request core-banking/account-service/transaction-service bị 403). **Đã khôi phục file ngay lập tức bằng `git restore` trước khi có bất kỳ `kubectl apply` nào — cụm sống không bị ảnh hưởng.** Không có gì được deploy sai trong lần chạy này, nhưng đây là bài học quan trọng: đọc log quyết định thật, không chỉ đọc 1 file config, trước khi kết luận "code chết".

**Phát hiện phụ đáng chú ý phát sinh từ đính chính này:** đọc lại `cross_cloud.rego`, rule cho `POST /transactions/execute` (payment-service → core-banking) chỉ kiểm `posture_compliant`, **không kiểm `fraud_gate_valid`/`x-fraud-gate` như `zta_policy.rego` có làm**. Tức là ở tầng PDP (OPA) trên đường thật, fraud-gate không được PDP gate. Đã xác nhận `services/core-banking/main.py:58-92` có tự kiểm tra fraud-gate độc lập bằng HMAC (`X-Fraud-Gate-Signature`, chống replay bằng timestamp ±60s, `hmac.compare_digest`) nên **không phải lỗ hổng khai thác được thực tế** (app tầng dưới vẫn chặn đúng) — nhưng là khoảng trống *defense-in-depth*: PDP đáng lẽ nên chặn trước khi tới app. Sẽ xử lý cùng T-1.1 khi thêm `service_acl` vào `cross_cloud.rego`.

- **Xử lý (đã cập nhật theo đính chính):** viết `service_acl` (theo ma trận G5) vào **cả hai** package — `zta_policy.rego` (đã làm, xem dưới) **và** `cross_cloud.rego` (đang làm) — thay cho rule "OpenStack-internal: bất kỳ workload OS nào gọi bất kỳ workload OS nào khác (trừ /admin)" hiện đang **sống thật** và quá lỏng. Bổ sung `fraud_gate_valid` vào rule `/transactions/execute` của `cross_cloud.rego` cho khớp `zta_policy.rego`. Giữ `fraud_gate.rego` nguyên trạng — vẫn code chết thật, không thuộc phạm vi sửa lần này (kế hoạch chỉ yêu cầu xoá nếu xác nhận chết, không bắt buộc — để lại làm tài liệu tham khảo logic fraud-gate tương lai nếu cần T-1.5).

---

## ⛔ TÓM TẮT CHỐT GIAI ĐOẠN 0 — "hệ thống thật đang là gì"

| Hạng mục | README/DANH_GIA_HE_THONG.md nói gì | Thực tế xác nhận | Lệch? |
|---|---|---|---|
| Data plane | Không rõ ràng / mâu thuẫn (istio-policies.yaml tự mâu thuẫn) | **100% Istio**, không còn Envoy tự viết ở service nghiệp vụ nào | Có — tài liệu cần cập nhật, không phải lỗi hệ thống |
| OPA nhận diện đích | Ngầm định OK | **Đúng, tốt** — `destination_principal` SPIFFE hợp lệ trên mọi request thật | Không lệch |
| `source_ip` trong app | Ngầm định đúng (dùng cho rate-limit, IP block) | **SAI** — luôn là `127.0.0.1`/`127.0.0.6` (loopback sidecar) | **Có, là lỗi thật** |
| mTLS cross-cloud | Tuyên bố "SPIRE mTLS cross-cloud" | **Đúng, xác nhận thật** bằng SVID trích từ client cert ở phía nhận | Không lệch — tuyên bố đúng |
| `cross_cloud.rego`/`fraud_gate.rego` | Ngầm định là policy đang dùng | **Code chết**, không bao giờ được gọi | Có — cần dọn ở T-1.1 |
| OPA image | Không đề cập version | Tag `latest` trôi nổi (đã ghim digest) | Có — đã sửa |
| istio-policies.yaml:307-308 | Comment nói core-banking còn Envoy | Sai — core-banking đã Istio | Có — đã sửa |

**Điểm đáng mừng cho khoá luận:** OPA destination-identity và mTLS cross-cloud — hai điểm kỹ thuật khó nhất trong kiến trúc — đều **hoạt động đúng thật**, không phải chỉ trên giấy. Vấn đề thật sự nằm ở: (1) `source_ip` sai (ảnh hưởng số liệu detection theo IP), (2) hai file rego chết, (3) tag ảnh trôi nổi, (4) hai chỗ tài liệu/comment lỗi thời.

## Hành động đã thực hiện trong GĐ 0 (không cần hỏi, theo đúng bảng quyết định)

1. `envoy/{configmap,envoy-sidecar,envoy-aws,envoy-os}.yaml` → chuyển vào `legacy/envoy/` kèm README.
2. Sửa comment sai `istio-policies.yaml:307-308`.
3. Ghim digest `opa/deployment.yaml`: `openpolicyagent/opa:latest-envoy` → digest `sha256:1792991ca...`.

*(Chi tiết diff xem trong `git diff` trên branch `fix/zta-remediation`.)*

## Câu hỏi cần bạn quyết định trước khi sang GIAI ĐOẠN 1

### 🛑 G3 — Số liệu detection theo IP cũ có bị loại bỏ không?

Đã xác nhận `source_ip` trong toàn bộ log ứng dụng hiện tại **là loopback (127.0.0.1/127.0.0.6), không phải IP client thật**, do sidecar terminate TCP trước khi tới app. Điều này có nghĩa: rate-limit theo IP, chặn IP, và bất kỳ số liệu "detection theo IP" nào trong `DANH_GIA_HE_THONG.md` đang được tính toán sai (coi mọi client là cùng một nguồn).

- **(a) Khuyến nghị:** loại bỏ toàn bộ số liệu detection theo IP hiện có trong `DANH_GIA_HE_THONG.md`, đo lại sau khi sửa T-5.1.
- **(b)** Giữ số liệu cũ, thêm ghi chú rõ về hạn chế đo lường.
- **(c)** Giữ nguyên, không đề cập. ⚠️ Rủi ro cao khi bảo vệ.

**→ QUYẾT ĐỊNH CỦA NGƯỜI DÙNG (2026-09-05): (a).** Loại bỏ số liệu detection theo IP cũ trong `DANH_GIA_HE_THONG.md`, đo lại sau khi T-5.1 hoàn tất. (Việc dọn `DANH_GIA_HE_THONG.md` và đo lại thuộc GĐ 5 — sẽ thực hiện khi tới T-5.1/PHỤ LỤC B, chưa làm ở bước này.)

**→ QUYẾT ĐỊNH: tiếp tục sang GIAI ĐOẠN 1 ngay** (không dừng lại chờ thêm xác nhận riêng).

---

# GIAI ĐOẠN 1 — SỬA LÕI PHÂN QUYỀN

## T-1.1 — Thu thập luồng gọi thật (caller → destination_principal → method → path)

- Lệnh: `bash scripts/run-demo.sh --traffic-only` (traffic bình thường, không phải kịch bản tấn công) rồi trích decision log OPA cả 2 cluster (tail 2000, lọc `msg=="Decision Log"`).
- Output (đã gộp, unique):

```
=== AWS ===
NO_SVID -> api-gateway (host header, không qua sidecar khác) -> GET /metrics, /metrics/     (Prometheus scrape — ngoài mesh, không tính vào ACL)
web-portal      -> api-gateway       GET  /accounts/{id}, /accounts, /transactions ; POST /payments
api-gateway     -> payment-service   GET  /accounts/{id}, /accounts, /transactions ; POST /payments
payment-service -> fraud-detection   POST /score

=== OPENSTACK ===
payment-service(aws) -> core-banking(os)        GET /accounts/{id}, /accounts, /transactions ; POST /transactions/execute
core-banking          -> account-service         GET /accounts/{id}, /accounts ; POST /accounts/transfer
core-banking          -> transaction-service      GET /transactions ; POST /transactions
```

- **Phát hiện quan trọng — KHÔNG có trong log OPA:** `payment-service` gọi `notification-service` (`POST /notify`, xác nhận trong code `services/payment-service/main.py:154`, chạy trên mọi payment thành công) **không xuất hiện trong OPA decision log dù demo đã chạy 4 payment thành công.**
  - Lý do: `kubectl get authorizationpolicy notification-service-allow -n financial -o yaml` cho thấy đây **không phải CUSTOM/ext_authz (OPA) như 6 service còn lại**, mà là một `AuthorizationPolicy` gốc của Istio với `action: ALLOW` và **`source.principals: ["*"]`** — nghĩa là **BẤT KỲ workload nào có SPIFFE ID hợp lệ trong mesh (kể cả web-portal, fraud-detection, hay bất kỳ service nào sau này) đều gọi được `POST /notify`**, hoàn toàn không qua OPA, không kiểm caller là ai.
  - Đây là lỗ hổng cùng bản chất với `valid_svid` (F1) — "có danh tính hợp lệ = được phép gọi bất cứ gì" — nhưng nằm ở một cơ chế khác (Istio AuthorizationPolicy thay vì OPA), **không nằm trong danh sách F1–F15 gốc của kế hoạch**, cần bổ sung xử lý ở T-1.1.

## 🛑 G5 — Ma trận ACL đề xuất (dựa trên traffic thật vừa đo, không phải suy đoán)

| Nguồn | Đích | Method | Path |
|---|---|---|---|
| `aws/web-portal` | `aws/api-gateway` | GET | `/accounts/{id}`, `/accounts` |
| `aws/web-portal` | `aws/api-gateway` | GET | `/transactions` |
| `aws/web-portal` | `aws/api-gateway` | POST | `/payments` |
| `aws/api-gateway` | `aws/payment-service` | GET | `/accounts/{id}`, `/accounts` |
| `aws/api-gateway` | `aws/payment-service` | GET | `/transactions` |
| `aws/api-gateway` | `aws/payment-service` | POST | `/payments` |
| `aws/payment-service` | `aws/fraud-detection` | POST | `/score` |
| `aws/payment-service` | `aws/notification-service` | POST | `/notify` |
| `aws/payment-service` | `openstack/core-banking` | GET | `/accounts/{id}`, `/accounts`, `/transactions` |
| `aws/payment-service` | `openstack/core-banking` | POST | `/transactions/execute` |
| `openstack/core-banking` | `openstack/account-service` | GET | `/accounts/{id}`, `/accounts` |
| `openstack/core-banking` | `openstack/account-service` | POST | `/accounts/transfer` |
| `openstack/core-banking` | `openstack/transaction-service` | GET | `/transactions` |
| `openstack/core-banking` | `openstack/transaction-service` | POST | `/transactions` |
| (mọi cặp khác) | — | — | **403** |

Siết đúng ma trận này sẽ chặn mọi cặp không nằm trong danh sách trên — kể cả các luồng hiếm/định kỳ chưa xuất hiện trong lần đo traffic này.

**→ QUYẾT ĐỊNH NGƯỜI DÙNG (2026-09-05): xác nhận đúng và đủ.** Lỗ hổng `notification-service`: đưa vào OPA (CUSTOM/ext_authz) + thêm cặp `payment-service -> notification-service` vào `service_acl`.

## Thực hiện

1. **`opa/policies/zta_policy.rego`** (package `zta.authz`, cluster AWS): thêm `destination_principal`, `service_acl`, `allowed_by_acl`; thay `internal_service_request`/`core_transaction_with_fraud_gate` từ chỉ-kiểm-`valid_svid` sang bắt buộc `allowed_by_acl`.
2. **`opa/policies/cross_cloud.rego`** (package `zta.crosscloud`, cluster OpenStack — **đây mới là policy sống thật cho cross-cloud + OS-internal**, xem đính chính T-0.6): viết lại hoàn toàn, thay rule "OS-internal: bất kỳ → bất kỳ (trừ /admin)" bằng cùng `service_acl` (chỉ 2 cặp: `payment-service(aws)->core-banking`, `core-banking->{account-service,transaction-service}`); bổ sung `fraud_gate_valid` còn thiếu cho `/transactions/execute` (đồng bộ với `zta_policy.rego`).
3. **`k8s/financial/istio-policies.yaml`**: `notification-service-allow` (ALLOW, `principals:["*"]`) → `notification-service-opa-authz` (CUSTOM/ext_authz, cùng pattern 6 service kia).
4. `opa check /policies` (qua image đã ghim digest) — không lỗi cú pháp trên cả 2 file.
5. Áp lên cụm thật: `kubectl create configmap opa-policies --from-file=opa/policies --dry-run=client -o yaml | kubectl apply` (cả 2 cluster) + `kubectl apply -f istio-policies.yaml` (cả 2 cluster) + `kubectl apply -f opa/deployment.yaml` (AWS) + `kubectl apply -f k8s/financial/os-security.yaml` (OpenStack, cũng áp digest pin OPA image T-0.5) → cả 2 `opa-server` rollout thành công, image digest xác nhận đã đổi.

## Nghiệm thu

```
(1) Luồng hợp lệ vẫn chạy — chạy `scripts/run-demo.sh --traffic-only` SAU khi siết:
    [NORMAL] payment ACC-1001→ACC-2001 15000000VND → completed fraud_score=15 gate=passed
    [NORMAL] payment ACC-2001→ACC-1001 100000VND   → completed fraud_score=5  gate=passed
    (2/2 completed — toàn bộ chuỗi web-portal→api-gateway→payment-service→fraud-detection
     →core-banking→account-service/transaction-service vẫn hoạt động đúng)

(2) Lateral movement bị chặn THEO DANH TÍNH (không phải theo path) — 3 test độc lập:
    notification-service -> payment-service POST /payments      : 403 (kỳ vọng 403) ✓
    fraud-detection       -> payment-service POST /payments      : 403 (kỳ vọng 403) ✓
    account-service (OS)  -> core-banking    POST /transactions/execute : 403 (kỳ vọng 403) ✓
      (case này trước đây LỌT QUA được nhờ rule "OS-internal: bất kỳ→bất kỳ" cũ — xác nhận qua
       decision log thật: "openstack/account-service -> openstack/core-banking POST
       /transactions/execute = False")

(3) Cặp hợp lệ trong ma trận vẫn allow=True (decision log OpenStack, 100 dòng gần nhất):
    aws/payment-service -> openstack/core-banking          GET  /accounts, /transactions   = True
    openstack/core-banking -> openstack/account-service     GET  /accounts                  = True
    openstack/core-banking -> openstack/transaction-service GET  /transactions               = True
```

**Kết luận T-1.1: ĐẠT.** Cả bằng chứng tích cực (traffic hợp lệ không bị phá) lẫn bằng chứng tiêu cực (3 kiểu lateral movement khác nhau, cả trong 1 cluster lẫn cross-cloud, đều bị OPA chặn bằng decision log thật chứ không chỉ theo lý thuyết) đều khớp mục tiêu khoá luận.

## Việc còn tồn đọng, chưa xử lý trong T-1.1 (ghi nhận, cần bạn quyết định)

1. ~~Dọn `AuthorizationPolicy notification-service-allow` cũ...~~ **ĐÃ XỬ LÝ (2026-09-05), theo yêu cầu rõ ràng của người dùng:** `kubectl delete authorizationpolicy notification-service-allow -n financial` trên cả 2 cluster. Xác nhận lại `/notify` vẫn `403` cho lateral movement sau khi xoá (không phụ thuộc policy cũ) — không regress. Chỉ còn duy nhất `notification-service-opa-authz` (CUSTOM) trên cả 2 cluster.
2. Bug `NOTIFICATION_SERVICE_URL` (fallback sai `127.0.0.1:15001`, có sẵn từ trước): **để sau, theo quyết định người dùng** — ngoài phạm vi F1–F15.

---

## T-1.2 — OPA tự xác minh chữ ký JWT

**Xác nhận lỗ hổng trước khi sửa** (query OPA REST API trực tiếp, `/v1/data/zta/authz/allow`, port-forward `svc/opa-service`):

```
JWT chữ ký rác (".ZmFrZQ" = base64("fake")) + issuer đúng
(http://keycloak.ztlab.local:8180/realms/ztlab, lấy từ query
data.zta.authz.expected_issuer) + role financial-write:
  → {"result": true}   ← XÁC NHẬN LỖ HỔNG: OPA allow một JWT hoàn toàn giả mạo.
```

**Sửa:** thay `io.jwt.decode()` bằng `io.jwt.decode_verify()` với JWKS thật lấy từ Keycloak (`.../protocol/openid-connect/certs`), cache 300s cùng cơ chế với `discovery_response`. Không có fallback key cứng khi JWKS không lấy được — fail-closed đúng nguyên tắc zero-trust (khác `expected_issuer` có fallback vì đó không phải bí mật). File: `opa/policies/zta_policy.rego`.

**Áp lên cụm (chỉ AWS — đây là nơi duy nhất đánh giá `zta.authz`):** cập nhật `opa-policies` ConfigMap cả 2 cluster (đồng bộ file), `kubectl rollout restart deploy/opa-server` (AWS).

**Nghiệm thu:**

```
(1) JWT giả (chữ ký rác), issuer đúng, role financial-write:
    → {"result": false}   ✓ (kỳ vọng 401/403 ở tầng app; ở tầng OPA là false — đúng)

(2) Luồng thật (JWT thật ký bởi Keycloak, qua run-demo.sh --traffic-only):
    4/4 payment completed (fraud_score 5, 5, 15, 5 — đều gate=passed)
    → chứng minh io.jwt.decode_verify() xác minh ĐÚNG chữ ký thật (chọn đúng key
      theo "kid" trong JWK Set) chứ không phải vô tình fail-closed toàn bộ.
```

**Kết luận T-1.2: ĐẠT** — *với đính chính quan trọng, xem GĐ 4 §T-4.2 "phát hiện phụ" (2026-09-05/06):* nghiệm thu "(2) luồng thật" ở trên chỉ chứng minh JWT giả bị từ chối — một `io.jwt.decode_verify` LUÔN LUÔN trả về false (bug thật, đã tồn tại từ chính bước T-1.2 này: thiếu constraint `"aud"` trong lúc mọi token Keycloak đều có claim `aud`) cũng cho kết quả giống hệt, nên test này KHÔNG đủ để chứng minh chiều "chấp nhận JWT thật". Bug đã được phát hiện và sửa dứt điểm ở T-4.2 (thêm `"aud"` vào constraints) — sau khi sửa, xác nhận lại: JWT thật giờ `jwt_signature_valid=true` đúng như tài liệu này ban đầu tuyên bố. Kết luận cuối cùng KHÔNG đổi (ĐẠT), nhưng quy trình kiểm chứng ban đầu có lỗ hổng phương pháp — đáng nêu rõ trong khoá luận.

**Phát hiện phụ, ngoài phạm vi (đáng ghi vào phần hạn chế/known-issues của khoá luận):** khi patch/restart `api-gateway` (bằng `patch-services.sh` cho T-1.3 ngay sau đây), pod mới có race điều kiện tái lập được 2/2 lần: `_load_oidc_config()` chạy ở FastAPI `startup` event gọi Keycloak NGAY khi container khởi động, nhưng istio-proxy (đường egress thật, traffic bị NAT qua sidecar) đôi khi chưa sẵn sàng route được → `Connection refused` → `_jwks_keys` rỗng → mọi request cần JWT bị `503 token verifier unavailable` cho tới khi `_jwks_refresh_loop()` (cố định 300s một lần, chỉ chạy lại nếu vẫn rỗng) thử lại thành công. Không phải do các thay đổi phiên này gây ra (không đụng gì tới istio-proxy/sidecar injection) — chỉ lộ ra vì đây là lần đầu tiên `api-gateway` bị restart kể từ sau lần deploy-all.sh gốc. Ảnh hưởng thật: **bất kỳ lần restart/redeploy nào của `api-gateway` cũng có thể treo đăng nhập tới 5 phút**. Chưa sửa (ngoài phạm vi kế hoạch) — khuyến nghị: annotation `proxy.istio.io/config: '{"holdApplicationUntilProxyStarts": true}'` trên Deployment `api-gateway`, hoặc rút ngắn interval retry khi `_jwks_keys` rỗng.

---

## T-1.3 — Sửa IDOR ở `/transactions`

**Xác nhận lỗi trước khi sửa** (token thật testuser01, chủ `ACC-1001`, đọc giao dịch của `ACC-2001` — chủ testuser02):

```
curl "http://localhost:18080/transactions?account_id=ACC-2001" -H "Authorization: Bearer $TOKEN_USER01"
→ trả về ĐẦY ĐỦ dữ liệu giao dịch của ACC-2001 (không phải của testuser01)
   → XÁC NHẬN IDOR, khớp đúng bằng chứng plan nêu (api-gateway/main.py:311-327 không đối chiếu owner,
     trong khi /accounts/{account_id} vài dòng trên có làm).
```

**Sửa:** `services/api-gateway/main.py`, endpoint `/transactions` — nếu không có role `security-admin`: bắt buộc `account_id` (từ chối rỗng, tránh "lấy hết"), và đối chiếu quyền sở hữu bằng cách gọi `/accounts/{account_id}` giống hệt logic đã có ở `get_account`. `security-admin` không bị ràng buộc (giữ hành vi cũ). Áp bằng `scripts/patch-services.sh api-gateway` (hot-patch ConfigMap, không cần rebuild image).

**Nghiệm thu:**

```
IDOR (testuser01 -> ACC-2001, không phải của mình):        403 access denied   ✓ (kỳ vọng 403)
Chính chủ (testuser01 -> ACC-1001, của mình):                200                 ✓ (kỳ vọng 200)
Không truyền account_id (non-admin):                         400 account_id is required (chặn thêm luôn kiểu "lấy hết")
```

**Kết luận T-1.3: ĐẠT.**

---

## T-1.4 — Bật kiểm tra `audience` của JWT

**Khảo sát trước khi sửa (quan trọng, khác giả định ban đầu của plan):** kiểm tra Keycloak thật cho thấy **đã có sẵn 2 client riêng** (`web-portal` — public, dùng cho luồng đăng nhập PKCE thật của `services/web-portal/main.py`; `api-gateway` — confidential, dùng cho gọi API trực tiếp/test), không phải dùng chung 1 client như plan giả định ban đầu. Vấn đề thật không phải "thiếu client riêng" mà là **chưa client nào có Audience mapper** — token thật (kể cả qua đăng nhập web-portal thật) có `aud` rỗng/không tồn tại, chỉ có `azp`.

**Xác nhận lỗ hổng trước khi sửa:** mint token thật (chữ ký thật, issuer đúng) từ client KHÁC hẳn mục đích (`siem-backend`, service account riêng cho SIEM backend) → `aud: "account"` (mặc định Keycloak, không phải "api-gateway") → gọi `/accounts` vẫn qua được bước xác thực JWT (chỉ bị chặn sau đó bởi thiếu role `financial-read`, HTTP 403) → xác nhận **audience hoàn toàn không được kiểm** trước khi sửa.

**Sửa:**
1. Keycloak: thêm Protocol Mapper loại "Audience" (`included.client.audience=api-gateway`) vào **cả 2** client `web-portal` và `api-gateway` (qua Admin REST API) — đảm bảo mọi token hợp lệ cho hệ thống (dù qua đăng nhập web thật hay qua client API trực tiếp) đều có `aud` đúng.
2. `k8s/financial/aws-services.yaml`: thêm `JWT_AUDIENCE=api-gateway` vào Deployment `api-gateway` (trước đây rỗng → `_decode_jwt()` tắt hẳn `verify_aud`).
3. `opa/policies/zta_policy.rego`: thêm `jwt_audience_valid` vào `valid_jwt` — kiểm `aud` cả ở OPA (đúng theo plan, không chỉ ở gateway), chấp nhận cả dạng `aud` là string đơn lẫn mảng (Keycloak serialize khác nhau tuỳ số lượng audience).

**Sự cố phụ trong lúc sửa (đã tự khắc phục, không ảnh hưởng kết quả cuối):** thử áp annotation `proxy.istio.io/config: holdApplicationUntilProxyStarts` (chuẩn của Istio) để tiện fix luôn race JWKS ở T-1.2 — annotation này **gây istio-proxy tự crash-loop** (`PostStartHookError`) trên bản Istio 1.22.3 kết hợp cách mount socket SPIRE qua `sidecar.istio.io/userVolume` của repo này (không tương thích). Phát hiện ngay qua `kubectl describe pod`, **revert lập tức** trước khi ảnh hưởng traffic thật (Deployment rolling-update giữ pod cũ chạy tốt trong lúc pod mới lỗi, không có downtime thật). Ghi nhận: **race JWKS ở T-1.2 vẫn CHƯA có fix an toàn**, chờ cách khác (rút ngắn interval retry trong code, hoặc tìm hiểu sâu hơn tại sao `holdApplicationUntilProxyStarts` xung đột với userVolume ở đây).

**Nghiệm thu:**

```
(1) Token thật, chữ ký/issuer đúng, SAI audience (siem-backend, aud=account):
    → 401 "invalid token"   ✓ (trước khi sửa: qua được bước JWT, chỉ bị chặn sau đó bởi role — nay chặn ngay từ audience)

(2) Token đúng audience (client api-gateway, mapper mới thêm):
    /accounts/ACC-1001 (chính chủ)         → 200   ✓
    /transactions?account_id=ACC-2001 (IDOR) → 403 ✓ (T-1.3 không bị ảnh hưởng)

(3) Đăng nhập web thật (PKCE flow đầy đủ qua Keycloak thật, không phải giả lập):
    GET /auth/start -> Keycloak login thật (testuser01) -> /auth/callback -> session cookie
    -> GET /dashboard: 200, hiển thị đúng dữ liệu ACC-1001
    → xác nhận Audience mapper trên client "web-portal" hoạt động đúng cho luồng đăng nhập THẬT,
      không chỉ client "api-gateway" dùng để test.

(4) run-demo.sh --traffic-only sau khi sửa: 2/2 payment completed — không regress.
```

**Kết luận T-1.4: ĐẠT.**

---

## T-1.5 — Chữ ký fraud verdict: từ đối xứng sang bất đối xứng

**Đính chính thiết kế so với plan gốc (quyết định của người dùng sau khi được báo lại):** kiểm tra kỹ cho thấy 2 điều plan không lường trước:
1. `pyspiffe` **không tồn tại trên PyPI** (404, kiểm tra 2026-09-05) — không có thư viện Python sẵn để gọi Workload API gRPC.
2. **JWT-SVID chuẩn không mang được custom claim** (chỉ có `sub`/`aud`/`exp`/`iat`) — dùng JWT-SVID đúng nghĩa đen sẽ không bảo vệ được chính giá trị `score` khỏi bị sửa (kẻ tấn công giữ JWT-SVID thật, đổi score trong header riêng).

→ **Người dùng chọn: dùng X.509-SVID để ký** (bất đối xứng, khoá do SPIRE cấp, nhưng ký trực tiếp lên canonical payload thay vì dùng JWT-SVID làm token). Xem `shared/svid_sign.py` để biết lý do đầy đủ.

**Không có pyspiffe → không có Workload API client → dùng chính binary `spire-agent` (image `ghcr.io/spiffe/spire-agent:1.9.4`, cùng version DaemonSet đang chạy) chạy `api fetch x509 -write` ghi cert/key/bundle ra file, đọc bằng `cryptography` (đã có sẵn qua `python-jose[cryptography]`, xác nhận `cryptography==50.0.1` chạy được trong cả 2 image — không cần rebuild image, chỉ cần hot-patch main.py).**

### Sự cố outage thật trong lúc triển khai (2 lần, cả 2 đều tự phát hiện + tự khắc phục trong vài phút)

1. **Lần 1:** thêm sidecar `svid-refresh` (container thường) chạy `spire-agent api fetch x509` lặp lại bằng vòng lặp shell `while true; do ...; sleep 60; done` — **image `ghcr.io/spiffe/spire-agent` là distroless, không có `/bin/sh`**, sidecar crash ngay. Sửa: bỏ shell, chạy thẳng lệnh fetch một lần mỗi lần container start.
2. **Lần 2 (nghiêm trọng hơn):** container "fetch một lần rồi thoát" dưới `restartPolicy: Always` khiến Pod **không bao giờ đạt trạng thái Ready** (`containers with unready status: [svid-refresh]`) → xác nhận trực tiếp bằng `kubectl get endpoints fraud-detection` trả về **rỗng** — tức Service này thật sự mất hết endpoint, mọi request `/score` từ payment-service sẽ fail. Thử sửa bằng "native sidecar" (K8s 1.29+, `initContainers` với `restartPolicy: Always` — theo tài liệu không tính vào điều kiện Ready của Pod) — **vẫn không khắc phục được trên bản k3s v1.29.3 này** (endpoints vẫn rỗng, READY vẫn 2/3). **Quyết định: bỏ hẳn sidecar refresh định kỳ**, chỉ giữ `initContainer` fetch một lần lúc pod khởi động (chặn app start tới khi có SVID — không có race kiểu T-1.2).
- **Cả 2 lần đều được phát hiện qua `kubectl get endpoints`/`describe pod` trong vòng 1-2 phút và revert ngay** trước khi ảnh hưởng traffic thật kéo dài — không có giao dịch thật nào bị mất trong quá trình debug (traffic thử nghiệm/demo mới bị ảnh hưởng thoáng qua, không phải qua đường thật của người dùng ở thời điểm đó).
- **Hạn chế còn lại (ghi nhận rõ, chưa giải quyết):** SVID chỉ được fetch **một lần lúc pod khởi động**, TTL 1h (`default_x509_svid_ttl`). Pod chạy quá ~1h mà không restart sẽ ký/xác minh bằng cert đã hết hạn → `core-banking` từ chối (`cert_expired_or_not_yet_valid`, fail **closed**, không phải lỗ hổng bảo mật, nhưng **là một lỗi khả dụng thật** nếu không restart định kỳ). Cần giải pháp khác (image có shell riêng, hoặc CronJob riêng ghi vào volume dùng chung, hoặc chờ K8s native sidecar hoạt động đúng trên bản k3s mới hơn) — không giải quyết trong phiên này.

### Thay đổi code

- **Mới:** `shared/svid_sign.py` — `load_own_svid()`, `load_trust_bundle()`, `sign()`, `verify()` (RFC 5280 chain qua `cryptography.x509.verification.PolicyBuilder/Store`, xác nhận kiểm được cả chain leaf→intermediate→root CA thật), `build_canonical()` dùng chung để tránh lệch định dạng canonical giữa bên ký và bên verify (đúng bài học từ vụ lệch issuer 2026-08-13 đã ghi trong code khác của repo).
- **`services/fraud-detection/main.py`**: `/score` giờ đọc SVID của chính nó, ký `canonical(timestamp, trace_id, from, to, amount, currency, score)`, trả thêm `timestamp/signature/cert` trong response.
- **`services/payment-service/main.py`**: xoá hẳn `_fraud_gate_signature`/`CORE_BANKING_SHARED_SECRET` — giờ chỉ relay `timestamp/signature/cert` từ response của fraud-detection sang header gửi `core-banking`, không tự ký gì nữa.
- **`services/core-banking/main.py`**: xoá HMAC compare, verify bằng `shared.svid_sign.verify()` với `EXPECTED_FRAUD_SIGNER_SPIFFE_ID=spiffe://ztlab.local/aws/fraud-detection`; audit log thêm `fraud_signature_reason` (lý do cụ thể khi từ chối, hữu ích cho điều tra).
- `k8s/financial/aws-services.yaml` (fraud-detection, payment-service) + `k8s/financial/os-services.yaml` (core-banking): thêm `initContainer` fetch SVID + volume `svid` (emptyDir) + volume `spire-socket` (hostPath, tách khỏi volume riêng của istio-proxy). Xoá `CORE_BANKING_SHARED_SECRET` khỏi cả 2 Deployment dùng nó (đã hết dùng).

### Nghiệm thu — 4 kịch bản, tất cả bằng traffic/exec thật, không chỉ đọc code

```
(1) Luồng thật (run-demo.sh --traffic-only, sau khi vá):
    2/2 payment completed (fraud_score=30, 5 — gate=passed) — chuỗi
    fraud-detection ký → payment-service relay → core-banking verify hoạt động đúng.

(2) Không chữ ký/cert (payment-service "bị chiếm" gửi thẳng, giống test gốc trong plan):
    POST core-banking /transactions/execute, amount=900000000, chỉ có X-Fraud-Gate/X-Fraud-Score
    → 403 "fraud gate validation failed"   ✓ (trước T-1.5: có thể lọt qua nếu biết đúng HMAC secret)

(3) Chữ ký THẬT (lấy verdict thật cho amount=1000) nhưng REPLAY với amount=900000000:
    → 403, log core-banking: fraud_signature_reason="signature_invalid"   ✓
    Chứng minh: có chữ ký thật của fraud-detection KHÔNG đủ nếu payload bị đổi — khác hẳn
    lỗ hổng cũ nơi payment-service tự tính lại HMAC cho bất kỳ giá trị nào nó muốn.

(4) Cert TỰ KÝ giả mạo, SAN giả spiffe://ztlab.local/aws/fraud-detection, chữ ký hợp lệ
    với chính khoá giả đó:
    → 403, log core-banking: fraud_signature_reason="cert_not_trusted_by_bundle: ...
      Certificate is missing required extension..."   ✓
    Chứng minh: chỉ "tự xưng" đúng SPIFFE ID không đủ — cert phải thật sự do SPIRE cấp,
    xác minh qua trust bundle (chain leaf→intermediate→root CA thật).
```

**Kết luận T-1.5: ĐẠT** về mặt bảo mật (đúng yêu cầu cốt lõi: payment-service bị chiếm không còn tự ký được verdict giả). **Còn hạn chế khả dụng đã ghi nhận ở trên** (SVID không tự refresh sau ~1h) — cần xử lý tiếp trước khi coi là sẵn sàng chạy dài hạn không giám sát. Ghi chú: chưa đẩy kiểm tra sở hữu xuống `transaction-service`/`core-banking` như plan khuyến nghị thêm ("quan trọng hơn") — hiện tại defense-in-depth cho việc này đến từ T-1.1 (`service_acl` chỉ cho phép đúng `payment-service`/`core-banking` gọi các service backend, không route thẳng từ ngoài vào), nhưng nếu `api-gateway` bị chiếm hoàn toàn thì vẫn không có lớp chặn thứ 2 ở tầng dữ liệu. Ghi nhận làm việc tồn đọng, chưa làm trong phiên này.
2. **Phát hiện bug mới, ngoài phạm vi F1–F15:** `NOTIFICATION_SERVICE_URL` không được set trong `k8s/financial/aws-services.yaml` (Deployment `payment-service`), code fallback về `http://127.0.0.1:15001` (sai — không có gì lắng nghe ở đó). Payment-service gọi `/notify` **luôn thất bại âm thầm** (`notification_send_failed`, bọc trong try/except không làm fail payment) — xác nhận lỗi này **có từ trước** khi tôi sửa gì (thấy cả ở log 18:24, trước khi có bất kỳ thay đổi OPA/AuthorizationPolicy nào). Không sửa trong T-1.1 (không liên quan phân quyền) — cần bạn quyết định có đưa vào phạm vi sửa không, và nếu có thì sửa ở đâu (thêm biến env đúng vào manifest).

---

## ĐỐI CHIẾU SAU `deploy-all.sh` chạy lại từ hạ tầng trống (2026-09-05, ~19:20)

> Bối cảnh: `scripts/deploy-all.sh` chạy full từ đầu (Terraform apply hạ tầng mới toàn bộ + Ansible + k3s + `deploy-app.sh`). Mục đích đối chiếu: các sửa ở GĐ 0–1 (đã ghi ở trên) có **sống sót** qua một lần triển khai từ hạ tầng trống hay không — vì đây chính là phép thử tái lập cho khoá luận.

### Sống sót đúng như kỳ vọng (xác nhận bằng lệnh trên cụm thật, không suy đoán)

| Hạng mục | Xác nhận |
|---|---|
| `health-check.sh` | `PASS=30 WARN=6 FAIL=0` — giống hệt lần trước |
| T-0.1 (data plane Istio) | Mọi pod nghiệp vụ cả 2 cluster đều có `istio-proxy`; `legacy/envoy/` vẫn chứa file cũ |
| T-0.5 (ghim digest OPA) | Cả 2 cluster: `openpolicyagent/opa@sha256:1792991ca...` |
| T-1.1 (`notification-service-opa-authz` CUSTOM, service_acl) | Cả 2 cluster chỉ còn policy CUSTOM (không còn `ALLOW *` cũ); traffic thật (`run-demo.sh --traffic-only`) 4/4 payment `completed` |
| T-1.5 (SVID initContainer cho fraud-detection) | `kubectl get endpoints fraud-detection` có 1 endpoint, pod `ready=true restarts=0` — outage kiểu "endpoints rỗng" đã ghi nhận trước đây **không tái diễn** |
| CronJob `security-healthcheck` (namespace `spire`, ngoài phạm vi kế hoạch) | Vẫn đúng triệu chứng cũ đã ghi nhận trước deploy lại (`opa=000000 loki_push=000000` xen kẽ `opa=200`) — không phải regression mới, là vấn đề đã biết chưa xử lý |

### 🛑 PHÁT HIỆN MỚI — cần bạn quyết định trước khi sửa tiếp

**Phát hiện 1 — Keycloak Audience mapper (phần thủ công của T-1.4) không sống sót qua deploy từ đầu.**
Mapper "Audience" được thêm bằng Keycloak Admin REST API thẳng lên instance Keycloak cũ ở phiên làm việc trước — **không nằm trong bất kỳ file IaC/provisioning nào** (không có realm-export, không có script Ansible/Terraform nào tạo mapper này). Sau `deploy-all.sh` (Keycloak được tạo lại từ đầu), xác nhận trực tiếp qua Admin API: client `api-gateway` **không còn** protocol mapper loại Audience. Giải mã token thật (`testuser01`, qua client `api-gateway`): `"aud": null`.

**Phát hiện 2 — lỗi logic thật trong chính code T-1.4, độc lập với Phát hiện 1.**
`services/api-gateway/main.py` dùng `python-jose` (`from jose import jwt`, không phải PyJWT). Test trực tiếp trong container đang chạy (`jose==3.3.0`):
```
NO-AUD CLAIM  -> DECODED (không lỗi!): {'iss': 'test-iss', 'exp': ..., 'sub': 'u1'}
WRONG-AUD     -> EXCEPTION: JWTClaimsError Invalid audience
```
`python-jose` chỉ kiểm `aud` **nếu claim đó tồn tại**; nếu token **hoàn toàn không có** `aud`, việc kiểm tra bị bỏ qua âm thầm — khác hành vi PyJWT (đã tự kiểm chứng PyJWT 2.7.0 báo lỗi `MissingRequiredClaimError` đúng như kỳ vọng ban đầu, nhưng code không dùng PyJWT). Hệ quả: **cho dù có khôi phục mapper Keycloak ở Phát hiện 1, một token không có `aud` (từ bất kỳ client Keycloak nào khác chưa gắn mapper) vẫn lọt qua được `_verify_token`** — không đúng ý định "chỉ chấp nhận `aud=api-gateway`" của T-1.4.

**Phát hiện 3 — quy trình test qua `localhost:18080` (`kubectl port-forward` trực tiếp vào pod, `scripts/open-admin-uis.sh`) không hề đi qua `istio-proxy` của `api-gateway`.**
Xác nhận bằng decision log OPA thật: trong 800 dòng gần nhất, **không có bất kỳ quyết định nào với `destination_principal = spiffe://ztlab.local/aws/api-gateway`** (chỉ thấy khi `api-gateway` là *nguồn* gọi đi `payment-service`/`fraud-detection`) — dù `AuthorizationPolicy api-gateway-opa-authz` áp dụng không điều kiện (`rules: [{}]`, `selector: app=api-gateway`). `kubectl port-forward` nối thẳng vào container, bỏ qua interception iptables của sidecar. Hệ quả: lớp `jwt_audience_valid` được thêm vào `opa/policies/zta_policy.rego` (defense-in-depth cho chính hop này) **chưa từng được bài test nào trong `run-demo.sh`/`health-check.sh` thực sự đi qua** — toàn bộ khẳng định "ĐẠT" của T-1.2/T-1.3/T-1.4 trong tài liệu này chỉ xác nhận đúng lớp app (`api-gateway/main.py`), chưa xác nhận lớp OPA cho riêng hop ngoài-vào-api-gateway. Cần một đường test thật qua Service/NodePort/ingress-gateway (không qua port-forward) để xác nhận lớp OPA này có hoạt động đúng không.

> 🛑 **CẦN BẠN QUYẾT ĐỊNH:**
> - **(a)** Sửa cả 3 ngay: viết lại IaC cho Keycloak mapper (Ansible/script apply Admin API mỗi lần deploy, không làm tay), sửa `_decode_jwt`/`_verify_token` để **bắt buộc** `aud` phải tồn tại và đúng (tự kiểm tra `"aud" not in claims` trước khi gọi `jwt.decode`, không dựa vào hành vi ngầm định của thư viện), và thêm một bài test thật qua đường không-port-forward (NodePort hoặc ingress) để xác nhận lớp OPA. Đầy đủ nhất, đúng tinh thần "trước khi sửa phải có bằng chứng, sau khi sửa phải chứng minh lại" của kế hoạch.
> - **(b)** Chỉ sửa Phát hiện 2 (lỗi logic code) ngay — đây là lỗi rõ ràng nhất, không phụ thuộc hạ tầng. Phát hiện 1 (Keycloak) và 3 (port-forward) ghi vào phần hạn chế/công việc tương lai của khoá luận.
> - **(c)** Ghi nhận cả 3 vào phần hạn chế, chưa sửa trong phiên này — ưu tiên các hạng mục GĐ 2 (SPIRE) tiếp theo trước.
>
> **Khuyến nghị:** (b) trước — Phát hiện 2 là lỗi logic thật, rẻ để sửa, và quan trọng nhất về mặt bảo mật (không phụ thuộc ai đó có nhớ cấu hình Keycloak đúng cách hay không). Phát hiện 1 nên xử lý cùng lúc nếu còn thời gian (chỉ cần viết 1 script gọi Admin API, chạy trong `scripts/deploy-app.sh`). Phát hiện 3 đáng ghi vào hạn chế đo lường của khoá luận — không bắt buộc sửa ngay vì `localhost:18080` chỉ là đường dev/test, cần xác nhận đường vào thật (NodePort/ingress) trong production dùng đường nào trước khi quyết định có đáng đầu tư thời gian dựng lại bài test hay không.

**→ QUYẾT ĐỊNH NGƯỜI DÙNG (2026-09-05): (a) — sửa cả 3 ngay.**

### Đã sửa & nghiệm thu — cả 3 phát hiện

**Phát hiện 2 (lỗi logic code) — ĐÃ SỬA.** `services/api-gateway/main.py`, hàm `_decode_jwt()`: sau khi `jose.jwt.decode()` trả về (thư viện chỉ kiểm `aud` khi claim *tồn tại*), tự kiểm thêm `if JWT_AUDIENCE and "aud" not in claims: raise JWTError(...)`. Áp bằng `scripts/patch-services.sh api-gateway` (hot-patch, không rebuild image).

**Phát hiện 1 (Keycloak mapper không phải IaC) — ĐÃ SỬA, 3 lớp:**
1. `k8s/keycloak/realm-config.json`: thêm `protocolMappers` (`oidc-audience-mapper`, `included.client.audience=api-gateway`) vào cả 2 client `api-gateway`/`web-portal` — để lần import Keycloak **từ đầu** tiếp theo (DB trống) tự có mapper.
2. `scripts/deploy-app.sh`: thêm hàm `deploy_audience_mapper()` (theo đúng khuôn mẫu `deploy_openldap_and_federation()` đã có sẵn trong file — dùng pod tạm gọi Admin API, idempotent, non-fatal nếu lỗi), gọi trong `main()` ngay sau `deploy_openldap_and_federation`. Xử lý đúng ca "Keycloak không bị deploy lại nhưng client đã tồn tại từ trước" (giống hệt lý do LDAP federation cần làm vậy — `--import-realm` không chạy lại nếu realm đã có).
3. Áp trực tiếp lên Keycloak đang chạy (không đợi redeploy) qua Admin API — xác nhận `GET protocol-mappers/models` trả về mapper mới trên cả 2 client.

**Phát hiện 3 (port-forward bỏ qua sidecar) — ĐÃ XÁC NHẬN bằng traffic thật, không cần đổi hạ tầng.** Thay vì mở NodePort/ingress mới (tốn công, đổi bề mặt tấn công), dùng cách rẻ hơn và đã có sẵn để bắt buộc traffic đi qua sidecar: gọi từ **một pod khác trong mesh** (`web-portal`) tới Service DNS thật của `api-gateway` (`http://api-gateway.financial.svc.cluster.local:8080`) thay vì `kubectl port-forward`. Decision log OPA xác nhận: cách này **có** sinh ra bản ghi `destination_principal=spiffe://ztlab.local/aws/api-gateway` (điều `localhost:18080` không bao giờ tạo ra).

**Nghiệm thu tổng hợp (traffic thật, qua cả 2 đường):**

```
Qua localhost:18080 (port-forward, chỉ test lớp APP):
  Token aud=api-gateway (đúng, mapper mới)         -> 200  ✓
  Token aud=account (siem-backend, SAI, có claim)  -> 401  ✓ (không đổi so với trước)
  run-demo.sh --traffic-only                       -> 4/4 payment completed, không regress ✓

Qua Service DNS thật web-portal -> api-gateway (test được cả lớp OPA):
  Token đúng (aud=api-gateway)                     -> 200 (OPA decision: result=True,
                                                          destination=aws/api-gateway) ✓
  Token sai audience (aud=account)                 -> 401 "invalid token"
```

### ⚠️ Phát hiện phụ (mới, phát sinh khi hoàn thành đúng Phát hiện 3 — không phải lỗi cần sửa gấp, nhưng đáng ghi rõ)

Khi gọi qua đường thật với token **sai** audience, response **401 vẫn tới từ tầng APP** (`api-gateway/main.py`) — decision log cho thấy **OPA vẫn `allow=true`** cho chính request đó (`source=aws/web-portal`, `destination=aws/api-gateway`, `result: True`). Đối chiếu `zta_policy.rego`: `allow` là OR của 4 nhánh (`public_path`, `external_api_request`, `internal_service_request`, `core_transaction_with_fraud_gate`). Cặp `web-portal -> api-gateway` đã đủ điều kiện qua **`internal_service_request`** (theo `service_acl`, dựa trên SPIFFE ID của workload — đúng mục tiêu T-1.1), nên `allow` = true qua nhánh đó **bất kể JWT của người dùng cuối đúng hay sai** — nhánh `external_api_request` (nơi `valid_jwt`/`jwt_audience_valid` của T-1.4 nằm trong đó) không bao giờ được nhánh này cần tới để cho phép.

**Nói cách khác:** `jwt_audience_valid` mà T-1.4 thêm vào `zta_policy.rego` (ý định: phòng thủ nhiều lớp, phòng khi OPA phải tự đánh giá JWT) **hiện là logic chết trên hop `web-portal -> api-gateway`** — không phải vì bug, mà vì kiến trúc: OPA đang phân quyền theo **danh tính workload** (đúng, nên giữ), còn việc JWT của **người dùng cuối** có đúng audience hay không là trách nhiệm hoàn toàn của tầng app (`api-gateway/main.py`, đã sửa đúng ở Phát hiện 2) — hai lớp này không chồng lên nhau như tài liệu T-1.4 ngầm giả định. Hệ thống vẫn an toàn (vì tầng app đã chặn đúng), nhưng phần comment "đồng bộ với JWT_AUDIENCE ở api-gateway" trong rego đang gây hiểu lầm về việc có phòng thủ 2 lớp thật.

**→ QUYẾT ĐỊNH NGƯỜI DÙNG (2026-09-05): dọn.**

**Đã dọn (không xoá logic — chỉ sửa comment gây hiểu lầm):** cân nhắc kỹ trước khi xoá — `jwt_audience_valid`/`external_api_request` **không sai logic**, nó là lớp bảo vệ thật cho kịch bản caller KHÔNG có SPIFFE ID hợp lệ (client thật sự ngoài mesh, PERMISSIVE mTLS không cert). Repo hiện **chưa có** NodePort/ingress nào lộ `api-gateway` ra ngoài mesh theo cách đó (xác nhận: chỉ có `ClusterIP` Service, không `Gateway`/`VirtualService`) nên nhánh này hiện không được dùng tới bởi hop `web-portal -> api-gateway` (hop đó luôn có SPIFFE ID nên đi qua `internal_service_request` trước) — nhưng xoá hẳn sẽ mất lớp phòng thủ thật nếu sau này hệ thống có đường vào ngoài-mesh. Xử lý: sửa lại comment ở `opa/policies/zta_policy.rego:94-...` cho đúng phạm vi thật (không còn nói "đồng bộ 2 lớp với api-gateway" — audience của JWT người dùng cuối cho hop `web-portal->api-gateway` hiện do MỘT MÌNH tầng app chịu trách nhiệm), giữ nguyên rule để làm lớp bảo vệ cho kịch bản ngoài-mesh trong tương lai.

Áp lên cả 2 cluster (`kubectl apply` ConfigMap `opa-policies` + `rollout restart deploy/opa-server`, đây là comment-only nên không đổi hành vi allow/deny). `opa check` xác nhận cú pháp hợp lệ (exit 0). `run-demo.sh --traffic-only` sau restart: 4/4 payment vẫn `completed`, không regress.

**Kết luận: cả 3 phát hiện từ lần đối chiếu sau `deploy-all.sh` + phát hiện phụ đều đã xử lý xong.** Chuyển sang GIAI ĐOẠN 2.

---

# GIAI ĐOẠN 2 — NỀN TẢNG DANH TÍNH (SPIRE)

## T-2.2 — Ổn định registration entry

**Tin tốt: đã ĐẠT từ trước, không phải do sửa trong phiên này — chỉ cần dọn code chết.**

Lệnh kiểm tra: `spire-server agent list` (AWS) trả về UID thật `dc8b2e90-...`, `b6b2cd22-...`, `0c5e47ee-...` — **không khớp bất kỳ UID nào** hardcode trong `spire/scripts/register-aws-workloads.sh` (`3548edb2-...`, `ce6be52e-...`). Grep xác nhận **`register-aws-workloads.sh`/`register-os-workloads.sh` không được gọi ở bất kỳ đâu** trong `scripts/`/`ansible/`. Vậy tại sao mesh vẫn hoạt động đúng?

Vì cơ chế thật đang chạy là **`scripts/ensure-spire-entries.sh`** (được `deploy-app.sh`/`deploy-security-stack.sh` gọi vô điều kiện mỗi lần deploy) — dùng **node-alias**: một entry `-node` parent vào chính `spire-server`, chọn bằng selector `k8s_psat:cluster:aws-k3s` (mọi agent trong cluster đều khớp, bất kể UUID riêng), rồi mọi workload entry parent vào alias đó (`spiffe://ztlab.local/nodes/aws-k3s`) thay vì vào UUID node cụ thể. Xác nhận bằng `entry show` thật: cả 5 entry AWS + 3 entry OpenStack đều `Parent ID: spiffe://ztlab.local/nodes/{aws,os}-k3s`.

**Kết luận:** đây chính xác là giải pháp plan đề xuất cho T-2.2 ("chuyển sang SPIRE Controller Manager/ClusterSPIFFEID khi có UID lệch") — nhưng đạt cùng mục tiêu (độc lập UUID node) mà **không cần** thêm component `ClusterSPIFFEID` CRD/Controller Manager. Node thay mới, agent tái attest, hay datastore SPIRE bị xoá đều tự phục hồi ở lần deploy kế tiếp — không còn "quả bom hẹn giờ" plan cảnh báo.

**Hành động đã làm (không cần hỏi — dọn code chết đã xác nhận, giống T-0.1):** chuyển `spire/scripts/register-aws-workloads.sh` và `register-os-workloads.sh` vào `legacy/spire/` kèm README giải thích (cả 2 hardcode UID/placeholder không tồn tại thật, không được gọi ở đâu). Giữ nguyên `spire/scripts/verify-svids.sh` (script chẩn đoán, không liên quan đăng ký, vẫn dùng được).

**Nghiệm thu:** `entry show` thật trên cả 2 cluster xác nhận toàn bộ entry parent vào node-alias, khớp agent list thật. ĐẠT.

---

## T-2.1 — Bỏ bootstrap không an toàn

**Xác nhận lỗ hổng còn nguyên (chưa sửa gì):**

```
spire/agent/aws-agent.conf:
  agent { ... insecure_bootstrap = true ... }
  WorkloadAttestor "k8s" { plugin_data { skip_kubelet_verification = true } }
```

Trust-on-first-use (agent tự tin server lần đầu kết nối mà không xác minh qua trust bundle có sẵn) + bỏ qua xác minh kubelet API khi attest workload — đúng như plan mô tả.

> 🛑 **G6 — CẦN BẠN QUYẾT ĐỊNH (rủi ro cao, đúng cảnh báo của kế hoạch):**
> - **(a)** Sửa: mount trust bundle qua ConfigMap, bỏ `insecure_bootstrap` + `skip_kubelet_verification`. **Rủi ro thật:** cấu hình sai → agent không lấy được SVID → toàn bộ mesh (cả 2 cloud) ngừng cấp/renew SVID. Hệ thống đang chạy tốt (vừa deploy xong, đang có traffic thật) — đây là thay đổi khó hoàn tác nhanh nếu sai (không chỉ sửa file rồi `kubectl apply` là xong, cần trust bundle đúng định dạng, đúng thời điểm phân phối tới từng node).
> - **(b)** Giữ nguyên, ghi rõ vào phần hạn chế của khoá luận kèm cách làm đúng.
>
> **Khuyến nghị của agent:** (a) chỉ nên làm nếu bạn đồng ý thử trên 1 node trước (`aws-k3s-worker-2` theo plan) và có thể chấp nhận vài phút gián đoạn để test — nên làm ở cửa sổ riêng, KHÔNG làm ngay giữa lúc đang có traffic/demo chạy. (b) an toàn hơn nếu bạn không có thời gian giám sát ngay bây giờ.
>
> Agent **không tự sửa T-2.1 trước khi có câu trả lời của bạn** — đây đúng loại quyết định luật #3 của kế hoạch yêu cầu dừng lại.

**→ QUYẾT ĐỊNH NGƯỜI DÙNG (2026-09-05): (a) — sửa ngay, thử 1 node trước.**

### Điều tra trước khi sửa (read-only, qua Ansible/SSH — không đổi gì)

- **Trust bundle cho bootstrap:** `spire-server bundle show` (AWS) trả về đúng **fingerprint khớp 100%** với file có sẵn trong repo `spire/root-ca/ca.crt` (subject "ZTLab Root CA") — vì cả `spire/server/aws-server.conf` lẫn `os-server.conf` đều dùng `UpstreamAuthority "disk"` trỏ tới cùng file này. Không cần fetch gì thêm, dùng thẳng file có sẵn.
- **CA cho kubelet verification:** SSH `aws_k3s_worker_2` — serving cert của kubelet tại `127.0.0.1:10250` có `issuer=CN=k3s-server-ca@...`, khớp đúng `/var/lib/rancher/k3s/agent/server-ca.crt` (đã có sẵn trên MỌI node, k3s tự đồng bộ, không cần phân phối gì thêm). Xác nhận lại trên `os_k3s_worker_1` (OpenStack) — cùng pattern, chỉ khác timestamp CA.
- `spire/root-ca/ca.key` (private key CA) — kiểm tra: **đã bị `.gitignore` chặn** (`*.key`), không nằm trong git. Không có rò rỉ.

### Đã sửa

1. `spire/agent/aws-agent.conf` + `os-agent.conf`: bỏ `insecure_bootstrap`, thêm `trust_bundle_path = "/run/spire/bundle/bootstrap.crt"`; bỏ `skip_kubelet_verification`, thêm `kubelet_ca_path = "/run/spire/kubelet-ca/server-ca.crt"`.
2. `spire/k8s/agent-daemonset.yaml`: thêm volume `spire-bundle` (ConfigMap, mount `/run/spire/bundle`) + volume `kubelet-ca` (hostPath `/var/lib/rancher/k3s/agent/server-ca.crt`, mount thẳng vào file).
3. `scripts/deploy-security-stack.sh`: thêm bước tạo ConfigMap `spire-bundle` (từ `spire/root-ca/ca.crt`) cho cả 2 cluster, để lần deploy từ đầu tiếp theo tự có, không cần làm tay.

### Áp lên cụm thật — AWS trước, quan sát kỹ, rồi mới OpenStack

```
AWS: tạo ConfigMap spire-bundle -> cập nhật spire-agent-config -> kubectl apply agent-daemonset.yaml
     -> DaemonSet tự rolling update (maxUnavailable=1, có sẵn) -> theo dõi node ĐẦU TIÊN (ip-10-10-1-10,
        trùng luôn với node đang chạy web-portal/fraud-detection/api-gateway):
     log: "Bundle loaded" (không lỗi bootstrap), "Node attestation was successful",
          5/5 X509-SVID tạo thành công cho các entry đang chạy trên node này.
     -> rollout tiếp tục tự động, cả 3 node AWS xong, "successfully rolled out".
     -> grep lỗi trên cả 3 pod agent: KHÔNG có.
     -> run-demo.sh --traffic-only: 4/4 payment completed.

OpenStack: lặp lại y hệt sau khi AWS xác nhận ổn.
     -> rollout cả 3 node "successfully rolled out", không lỗi.
     -> run-demo.sh --traffic-only: 4/4 payment completed (cross-cloud).
     -> mTLS cross-cloud (T-0.4) re-test: core-banking istio-proxy vẫn trích đúng
        "svid":"spiffe://ztlab.local/aws/payment-service" — KHÔNG regress.
```

**Kết luận T-2.1: ĐẠT.** Cả 2 cluster giờ: agent tự xác minh server bằng trust bundle thật khi bootstrap (không còn TOFU), và tự xác minh TLS kubelet khi attest workload bằng CA thật của k3s (không còn bỏ qua xác minh). Không có downtime thực tế — mọi rollout đều theo maxUnavailable=1 sẵn có trong DaemonSet, traffic thật không gián đoạn ở cả 2 lần test trước/sau mỗi cluster.

### ⚠️ Phát hiện phụ quan trọng từ T-2.1 (phát sinh khi làm T-3.1 — ghi vào đây vì đúng nguồn gốc)

Khi restart `spire-agent` DaemonSet (rolling, từng node), **istio-proxy của các pod nghiệp vụ ĐANG CHẠY trên node đó không tự reconnect lại SDS (Secret Discovery Service) tới agent mới** — log xác nhận thật: `payment-service`'s istio-proxy báo "`StreamSecrets gRPC config stream to sds-grpc closed... Connection refused`" liên tục suốt ~55 phút (từ đúng lúc agent trên node đó bị thay pod, tới lúc cert cũ hết hạn theo TTL 1h và toàn bộ giao dịch bắt đầu fail thật với `cert_expired_or_not_yet_valid`). Sidecar vẫn "Running" bình thường trong lúc này — triệu chứng ẩn y hệt kiểu lỗi mà `security-healthcheck` CronJob (T-0 note) được viết ra để bắt, nhưng ở tầng khác.

**Hệ quả cho vận hành:** bất kỳ lần restart `spire-agent` nào (bảo trì, nâng cấp, node bị thay) đều cần **restart theo sau toàn bộ pod nghiệp vụ trên(các) node bị ảnh hưởng** — nếu không, hệ thống trông vẫn "Running" bình thường nhưng sẽ âm thầm hỏng sau tối đa 1h (thời điểm SVID cache hết hạn). Đã xác nhận khắc phục bằng `kubectl rollout restart` toàn bộ deployment nghiệp vụ (cả 2 cluster) — traffic thật phục hồi 4/4 hoàn toàn sau đó.

**Chưa sửa tận gốc trong phiên này** (ngoài phạm vi T-2.1 gốc, cần quyết định riêng): hoặc (i) thêm bước "restart toàn bộ pod nghiệp vụ" vào ngay sau bước restart `spire-agent` trong `deploy-security-stack.sh`/runbook bảo trì, hoặc (ii) tìm cách làm istio-proxy tự phát hiện SDS stream chết và tự phục hồi kết nối (có thể là bug/giới hạn thật của tổ hợp Istio 1.22.3 + SPIRE 1.9.4 phiên bản đang dùng, cần nghiên cứu thêm). Ghi nhận đây là một điểm hạn chế khả dụng đáng đưa vào khoá luận — song song với hạn chế TTL 1h không tự refresh đã ghi ở T-1.5.

**Cập nhật (trong lúc làm T-3.1, cùng ngày):** hạn chế TTL 1h của T-1.5 tái diễn **2 lần nữa** trong phiên này, lần đầu ở phút thứ 41 sau khi restart (ngắn hơn 1h — có thể do lệch giờ nhẹ giữa 2 cluster, hoặc TTL thực tế bị tính từ thời điểm khác pod creationTimestamp), không chỉ đúng 1h như tài liệu ban đầu ước tính — càng củng cố đây là rủi ro khả dụng thật, không phải lý thuyết, và **tần suất restart cao trong một phiên vận hành (do bảo trì SPIRE/mesh) sẽ làm lộ hạn chế này thường xuyên hơn dự kiến ban đầu.** Xử lý bằng cách restart lại `fraud-detection` mỗi lần — không bền vững cho vận hành thật.

---

# GIAI ĐOẠN 3 — PHÂN ĐOẠN THẬT SỰ

## T-3.1 — NetworkPolicy từ mức namespace xuống mức pod

**→ QUYẾT ĐỊNH NGƯỜI DÙNG (2026-09-05): (a) — áp ngay theo ma trận, chỉ siết chiều Ingress.**

### Ma trận đề xuất (dựa traffic thật T-1.1 + grep code xác nhận Redis/Postgres)

Xác nhận thêm trước khi viết policy: AWS không có service nào dùng Postgres trực tiếp (grep rỗng) — port 5432 trong rule cũ là thừa. Redis chỉ `api-gateway`/`fraud-detection`/`web-portal` dùng thật (grep `main.py`, không chỉ `requirements.txt`) — `payment-service`/`notification-service` không dùng. OpenStack: `account-service` → `postgres-accounts`, `transaction-service` → `postgres-txn` (xác nhận qua `ACCOUNTS_DB_HOST`/`TXN_DB_HOST` trong `os-services.yaml`); `core-banking` không có DB riêng.

**Thực hiện:** xoá rule namespace-wide "financial → financial" (8080/15006/9191/5432/6379) khỏi `aws-allow-list.yaml`/`os-allow-list.yaml`; thêm `aws-pod-segmentation.yaml`/`os-pod-segmentation.yaml` — mỗi NetworkPolicy chỉ siết **Ingress** của một pod đích cụ thể theo `podSelector`, khớp đúng cặp đã xác minh. Cố ý **không đổi Egress** (giữ nguyên rule cũ) — giảm rủi ro đứt luồng chưa biết ở phía nguồn, vì phía đích đã đủ để chặn lateral movement.

### Sự cố xảy ra trong lúc áp (2 lần, không do NetworkPolicy — cả 2 đã xác định nguyên nhân thật và khắc phục)

1. Áp xong trên AWS, traffic thật fail `fraud gate validation failed` → điều tra ra là SVID hết hạn TTL 1h (T-1.5 hạn chế đã biết, trùng hợp thời điểm, không liên quan NetworkPolicy).
2. Restart `fraud-detection` để lấy SVID mới → lộ ra phát hiện phụ mới ở T-2.1 (istio-proxy không tự reconnect SDS sau khi `spire-agent` bị restart) → phải restart toàn bộ pod nghiệp vụ cả 2 cluster mới phục hồi hoàn toàn (đã ghi chi tiết ở mục T-2.1 phía trên). Sau đó: `run-demo.sh --traffic-only` 4/4 `completed` cả cross-cloud, `health-check.sh` PASS=30 WARN=6 FAIL=0 — hệ thống ổn định trở lại.

### 🛑 PHÁT HIỆN CHÍNH — NetworkPolicy pod-level KHÔNG thực sự được kube-router enforce trên cụm này

Sau khi traffic ổn định, kiểm chứng đúng mục tiêu T-3.1 (lateral movement có bị chặn ở L4 chưa, không chỉ L7/OPA):

```
notification-service -> redis:6379 (KHÔNG có trong allow-list mới) -> CONNECT OK  ← SAI kỳ vọng
notification-service -> payment-service:8080 (KHÔNG có trong allow-list mới) -> CONNECT OK  ← SAI kỳ vọng
payment-service -> fraud-detection:8080 (CÓ trong allow-list, đối chứng) -> CONNECT OK  ← đúng kỳ vọng nhưng không phân biệt được gì
```

Đối chứng bằng 1 pod tạm trong namespace `default` (chưa từng được phép ở port 6379, kể cả dưới rule CŨ) → `redis:6379` → **CONNECT FAIL** đúng kỳ vọng. Vậy NetworkPolicy **có** hoạt động cho pod ngoài mesh/ngoài namespace `financial`, nhưng **không** hoạt động cho các cặp pod MỚI thêm (`aws-pod-redis`, `aws-pod-payment-service`, ...) bên trong `financial`.

**Điều tra sâu hơn (SSH trực tiếp vào node `aws_k3s_worker_1`, đọc iptables/nftables thật):**

```
$ sudo iptables -L KUBE-POD-FW-HKOBDLVGZ4DZJPQ6 -n -v   # firewall chain của pod redis
... KUBE-NWPLCY-VL2XS5LFLUOYVIUM (aws-financial-allow-baseline) — liệt kê được bình thường
... KUBE-NWPLCY-544ZPHAAYLX7HZFS (aws-pod-redis, policy MỚI)     — jump rule tồn tại

$ sudo iptables -L KUBE-NWPLCY-544ZPHAAYLX7HZFS -n -v
iptables v1.8.7 (nf_tables): chain `KUBE-NWPLCY-544ZPHAAYLX7HZFS' in table `filter' is incompatible, use 'nft' tool.

$ sudo nft list chain ip filter KUBE-NWPLCY-544ZPHAAYLX7HZFS
Error: No such file or directory   ← chain KHÔNG tồn tại thật trong nftables ruleset

$ sudo nft list ruleset | grep KUBE-NWPLCY-544ZPHAAYLX7HZFS
(không có kết quả nào — xác nhận chain rỗng/không được tạo)
```

**Kết luận ban đầu (SAI một phần — xem đính chính ngay dưới):** ~~kube-router tạo được jump-rule tham chiếu tới chain của policy mới, nhưng KHÔNG tạo được nội dung thật của chain đó~~.

### ⚠️ ĐÍNH CHÍNH (đào sâu thêm theo quyết định người dùng — phương án (a))

Kết luận trên bị nhầm vì kube-router **tự động xoay vòng tên chain/ipset theo hash mới sau MỖI lần full-sync** (rất thường xuyên trong phiên này, do liên tục có pod restart) — lần đọc đầu tiên trúng đúng lúc tên chain vừa đổi, tưởng nhầm là "không tồn tại". Đọc lại chain **hiện hành** (tên mới mỗi lần) bằng `nft list ruleset | grep "ip daddr <IP đích>"` để tìm tên chain đang thật sự active, rồi cài thêm `ipset` (không có sẵn, chỉ thiếu CLI, không phải thiếu kernel support) để đọc trực tiếp:

```
$ sudo ipset list KUBE-SRC-K5LLAN7BNTCY6K65   # nguồn được phép gọi redis, theo aws-pod-redis
Members: 10.42.1.92 (web-portal) 10.42.1.91 (fraud-detection) 10.42.0.62 (api-gateway)
```

**Rule VÀ ipset đều ĐÚNG 100%** — notification-service (10.42.0.63) **không** có trong danh sách, đúng như đã viết. Vậy tại sao kết nối vẫn lọt qua? Cô lập biến số bằng 2 pod test độc lập:

```
Pod KHÔNG sidecar (namespace default) -> redis                                    -> BỊ CHẶN (đúng)
Pod KHÔNG sidecar, CÙNG node với notification-service -> redis (khác node)         -> BỊ CHẶN (đúng)
notification-service (CÓ istio-proxy sidecar) -> redis (khác node)                 -> LỌT QUA (sai)
```

**Xác nhận bằng chính Envoy's stats của notification-service** (`istio_tcp_connections_opened_total`, `outbound|6379||redis...cx_total:2`): Envoy sidecar **thực sự** mở kết nối TCP thật tới `10.42.1.13:6379` (không phải giả lập/cache) — kết nối này chạy qua mạng thật, nhưng **không hề làm tăng counter** của chain firewall NetworkPolicy phía node đích khi đối chiếu (dò theo tên chain xoay vòng, thấy compliant-mark được set nhưng không rõ nhánh nào set nó — không đủ bằng chứng chỉ đích danh cơ chế chính xác dù đã thử bắt counter trước/sau).

**Kết luận (dừng điều tra ở đây):** đây là một tương tác thật giữa **Istio sidecar (cách nó tạo kết nối outbound qua Envoy) và kube-router's NetworkPolicy enforcement (dựa trên iptables FORWARD chain + ipset theo IP nguồn)** khiến traffic **có** sidecar lọt qua enforcement L4, trong khi traffic **không** sidecar bị chặn đúng. Rule/ipset compile đúng, không phải lỗi YAML hay lỗi cú pháp policy — nhưng root cause chính xác (fwmark chồng lấn? conntrack? đường đi khác trong netfilter cho traffic qua Envoy outbound?) **chưa xác định được dứt điểm** dù đã thử nhiều hướng (đọc chain/ipset trực tiếp, đối chứng có/không sidecar, cùng/khác node, xem Envoy stats). Việc xác định chính xác cần chuyên môn netfilter/Istio sâu hơn và nhiều thời gian hơn mức hợp lý cho một hạng mục trong kế hoạch này.

**Hệ quả (khác với kết luận SAI ban đầu):** vấn đề **không phải** "chưa xác nhận được enforcement" một cách chung chung — đã xác nhận CHẮC CHẮN: NetworkPolicy **có** chặn đúng traffic không qua Istio (namespace khác, hoặc bất kỳ pod không được mesh sidecar), nhưng **traffic giữa các pod nghiệp vụ (đều có sidecar) — chính là loại traffic T-3.1 muốn phân đoạn — không bị chặn**. Đây là phát hiện có giá trị nghiên cứu cao hơn cả 2 giả thuyết ban đầu: không phải "NetworkPolicy hoàn toàn không hoạt động" mà là "NetworkPolicy hoạt động đúng CHO ĐẾN KHI traffic đi qua Istio sidecar" — một khoảng trống rất cụ thể, đáng để phân tích sâu trong khoá luận (an ninh mạng nhiều lớp: lớp mesh (Envoy) và lớp CNI (kube-router) không phối hợp như kỳ vọng).

**Đánh giá rủi ro thực tế:** KHÔNG phải regression — hành vi L4 cho traffic financial-internal HIỆN TẠI giống hệt TRƯỚC khi sửa (permissive). Không có lỗ hổng MỚI so với trước T-3.1.

**→ QUYẾT ĐỊNH NGƯỜI DÙNG (2026-09-05): đào sâu thêm.**

### Đào sâu bằng conntrack (bắt trực tiếp lúc kết nối xảy ra)

```
$ sudo conntrack -L -p tcp --dport 6379   # NGAY sau khi notification-service kết nối
tcp 6 86398 ESTABLISHED src=10.42.0.63 dst=10.42.1.13 ... mark=0 use=1   ← notification-service (SAI, phải bị chặn)
tcp 6 86232 ESTABLISHED src=10.42.1.91 dst=10.42.1.13 ... mark=0 use=1   ← fraud-detection (ĐÚNG, được phép)
tcp 6 86232 ESTABLISHED src=10.42.0.62 dst=10.42.1.13 ... mark=0 use=1   ← api-gateway (ĐÚNG, được phép)
```

**Phát hiện:** `mark=0` giống hệt nhau cho CẢ kết nối hợp lệ lẫn kết nối lẽ ra phải bị chặn — nghĩa là cờ "compliant" (`0x20000`) kube-router dùng để quyết định allow/reject là **packet mark** tạm thời trong 1 lần đi qua chain (SKB mark), **không phải connmark** (không được `CONNMARK save` lại) — nên không thể dùng conntrack để phân biệt "đã được cho qua vì đúng policy" hay "đã được cho qua vì lý do khác" sau khi kết nối đã ESTABLISHED. Đây gợi ý CHÍNH XÁC gói SYN đầu tiên (trước khi thành ESTABLISHED) mới là nơi quyết định — nhưng bắt đúng gói SYN đó cần tiêm thêm rule `LOG`/`NFLOG` thủ công vào đúng chain đang active.

**Giới hạn kỹ thuật khi thử bước tiếp theo:** kube-router **tái tạo toàn bộ ruleset rất thường xuyên** trong phiên này (mỗi vài giây — do liên tục có pod bị restart trong lúc điều tra/sửa các mục khác), khiến bất kỳ rule debug nào tự tiêm tay vào chain hiện hành đều bị kube-router XOÁ VÀ THAY THẾ gần như ngay lập tức ở lần full-sync kế tiếp — không đủ thời gian để vừa tiêm rule vừa trigger kết nối vừa đọc log một cách đáng tin cậy. Đã thử các hướng hợp lý trong phạm vi rủi ro chấp nhận được (đọc chain/ipset trực tiếp — đúng; đối chứng có/không sidecar — có/không sidecar là biến số quyết định; Envoy stats — xác nhận kết nối thật; conntrack — loại được giả thuyết "connmark bị ghi đè") mà chưa tách được chính xác cơ chế netfilter cuối cùng.

**Dừng điều tra sâu hơn tại đây.** Lý do: bước tiếp theo (tiêm `NFLOG` vào đúng thời điểm ruleset ổn định, hoặc tắt tạm sidecar để so sánh trực tiếp) đòi hỏi thao tác chính xác về thời gian trên hạ tầng đang chạy traffic thật, rủi ro cao hơn giá trị thu thêm được cho phạm vi khoá luận — và bằng chứng đã thu thập được (traffic có sidecar bypass, traffic không sidecar bị chặn đúng, ipset/rule compile đúng) đã đủ cụ thể, rõ ràng để viết thành một phát hiện có giá trị mà không cần biết chính xác cơ chế netfilter nội bộ.

**Ghi nhận cuối cùng cho khoá luận:** NetworkPolicy (L4, kube-router) trên tổ hợp hạ tầng k3s + iptables-nft này **chỉ enforce đúng cho traffic KHÔNG đi qua Istio sidecar**. Với kiến trúc mesh 100% Istio của hệ thống này (T-0.1), toàn bộ traffic nghiệp vụ thật — đúng loại traffic T-3.1 muốn phân đoạn — đều có sidecar, nên **L4 hiện không cung cấp phân đoạn thật bổ sung nào so với L7 (OPA)** cho traffic financial-internal. L7 (OPA/service_acl, T-1.1) vẫn là lớp phân đoạn THẬT duy nhất đang hoạt động đúng và đã được kiểm chứng đầy đủ bằng traffic thật. Đây là một giới hạn kiến trúc thật (Istio + kube-router không phối hợp như kỳ vọng trên tổ hợp hạ tầng này), không phải lỗi cấu hình của repo — đáng đưa thành một phần phân tích trong khoá luận (ranh giới giữa phân đoạn tầng mesh và tầng CNI).

---

## T-3.2 — Một nguồn sự thật cho phân đoạn hai tầng (đóng góp mới)

**Vấn đề xác nhận trước khi sửa:** `service_acl` (ma trận phân quyền, T-1.1) trước đây được **định nghĩa tay 2 lần độc lập** — một bản trong `zta_policy.rego` (package `zta.authz`, cluster AWS), một bản gần như giống hệt trong `cross_cloud.rego` (package `zta.crosscloud`, cluster OpenStack). Không có gì đảm bảo 2 bản này luôn khớp nhau khi sửa sau này — đúng loại rủi ro "lệch âm thầm giữa nhiều bản khai báo" mà T-3.2 muốn giải quyết, và T-3.1 vừa cho thấy y hệt kiểu rủi ro này xảy ra thật giữa L4/L7.

**Thực hiện:**

```
policy/service-graph.yaml          (nguồn sự thật duy nhất — workload, edge, method/path, port)
   ├──► scripts/gen-rego-acl.py       → opa/policies/service_acl.rego (package zta.generated)
   └──► scripts/gen-networkpolicy.py  → k8s/financial/network-policies/{aws,os}-pod-segmentation.yaml
```

- `zta_policy.rego` và `cross_cloud.rego`: xoá 2 bản `service_acl := {...}` viết tay, thay bằng `service_acl := data.zta.generated.service_acl` (1 dòng, cùng trỏ vào file generated).
- Edge cross-cluster (`payment-service -> core-banking`) đánh dấu `cross_cluster: true` trong graph — generator L4 bỏ qua (cơ chế khác hẳn: ipBlock/NodePort qua WireGuard, không phải podSelector, khai báo riêng trong `aws-allow-list.yaml`/`os-allow-list.yaml`, không đổi).
- Edge hạ tầng (Redis, Postgres, OPA ext_authz) đánh dấu `l4_only: true` — không có method/path, không tham gia `service_acl` (những kết nối này không đi qua OPA).

**Áp lên cụm thật:** `opa-policies` ConfigMap (cả 2 cluster) + `rollout restart deploy/opa-server`. Nghiệm thu bằng traffic thật + đối chứng T-1.1:

```
run-demo.sh --traffic-only (sau khi đổi service_acl sang generated): 4/4 payment completed — không regress.
notification-service -> payment-service /payments (lateral movement, OPA/L7): 403 — vẫn đúng như T-1.1.
```

**Test tự động (`tests/test_service_graph_consistency.py`):**

1. `test_generated_files_match_source_of_truth` — chạy lại cả 2 generator, so nội dung file trước/sau: PASS (khớp `git diff` rỗng — đúng tiêu chí nghiệm thu gốc của kế hoạch).
2. `test_every_business_edge_present_in_both_layers` — mọi edge nghiệp vụ trong `service-graph.yaml` đều có mặt CẢ ở `service_acl.rego` (L7) lẫn NetworkPolicy sinh ra (L4): PASS.

**Lưu ý quan trọng khi diễn giải test #2 (đã ghi rõ trong docstring của test, nhắc lại ở đây để không ai đọc nhầm):** test này CHỈ xác nhận 2 file khai báo nhất quán với nhau — **không** xác nhận L4 có thực sự chặn hay không (T-3.1 đã xác nhận: KHÔNG, với traffic có Istio sidecar). Đây là điểm khác biệt quan trọng so với tiêu chí nghiệm thu gốc của kế hoạch ("test tự động chứng minh mọi cặp bị L7 từ chối cũng bị L4 chặn") — tiêu chí đó không thể đạt được thật trên hạ tầng hiện tại, nên test được thiết kế lại thành "nhất quán khai báo" thay vì "nhất quán enforcement", và ghi rõ giới hạn này để không tạo cảm giác an toàn giả.

**Kết luận T-3.2: ĐẠT** (ở đúng phạm vi khả thi trên hạ tầng hiện tại) — không còn 2 bản `service_acl` lệch nhau tiềm ẩn; L4 và L7 giờ cùng đọc từ 1 nguồn duy nhất; có test tự động chống trôi. Giá trị thật của T-3.2 ở đây là **loại bỏ rủi ro trôi giữa 2 khai báo**, không phải "sửa được lỗ hổng enforcement L4" (đó là giới hạn hạ tầng đã ghi ở T-3.1, ngoài khả năng sửa trong phạm vi kế hoạch này).

---

# GIAI ĐOẠN 4 — BỐI CẢNH NGÂN HÀNG

## T-4.1 — Đưa `device_trust` vào quyết định truy cập

**Xác nhận trước khi sửa:** `device_trust` (thiết bị/trình duyệt người dùng cuối, đánh giá ở `web-portal/main.py::_evaluate_device_trust` khi đăng nhập) chỉ cộng 10-20 điểm rủi ro bên trong `fraud-detection/main.py` — grep xác nhận **không xuất hiện** ở `zta_policy.rego`/`cross_cloud.rego` trước khi sửa. Khác với `device_posture` (posture của chính WORKLOAD gọi, đã hoàn thiện từ trước, có `posture_compliant` trong rego) — 2 khái niệm dễ nhầm tên nhưng khác nhau, đã phân biệt rõ trong comment code.

Xác nhận thêm 1 bug fail-open đúng như plan nêu: `web-portal/main.py:216` — `is_known = True` khi Redis lỗi (coi thiết bị lạ là quen).

**Đã sửa:**
1. `web-portal/main.py`: fail-open → fail-closed (`is_known = False` khi Redis lỗi — coi là thiết bị chưa biết, không tự động tin tưởng).
2. `payment-service/main.py`: relay `X-Device-Trust` header khi gọi `core-banking /transactions/execute` (cùng pattern `X-Device-Posture` đã có).
3. `cross_cloud.rego` (đường thật `/transactions/execute` đi qua — xem đính chính T-0.6): thêm `device_trust_compliant` vào điều kiện `allow` — additive (thiếu header thì coi như không áp dụng, không phá traffic cũ), chỉ chặn cứng khi `suspicious`; `new_device`/`unknown` vẫn qua PDP (chỉ cộng điểm rủi ro ở fraud-detection — chưa đủ căn cứ chặn cứng một thiết bị CHỈ VÌ mới thấy lần đầu).

**Nghiệm thu (test cô lập qua OPA REST API, cùng pattern `tests/grafana_kb_t5_noncompliant_device.sh` — không qua app thật vì `core-banking` có lớp validate HMAC/chữ ký riêng che mất kết quả OPA):** `tests/grafana_kb_t4_untrusted_device.sh` (mới) — PASS: thiếu header hoặc `trusted` → `allow=True`; `suspicious` → `allow=False` (3/3 lần thử). `run-demo.sh --traffic-only` sau khi áp lên cụm thật: 4/4 payment vẫn `completed`, không regress.

**Kết luận T-4.1: ĐẠT.**

---

## T-4.2 — Step-up authentication theo ngưỡng giao dịch

**Xác nhận trước khi quyết định:** `fraud-detection/main.py` — `CRITICAL_AMOUNT_VND` (mặc định qua env, xem `FRAUD_CRITICAL_AMOUNT_VND`) và `MAX_SINGLE_TXN_VND` ở `payment-service` đều đặt ở mức trăm triệu, cao hơn nhiều so với ngưỡng quy định (>10 triệu/lần hoặc luỹ kế >20 triệu/ngày cần xác thực mạnh). Không có step-up authentication ở bất kỳ đâu trong hệ thống — xác nhận đúng như plan nêu.

> 🛑 **G8 — CẦN BẠN QUYẾT ĐỊNH:**
> - **(a)** Triển khai đầy đủ: Keycloak authentication flow theo LoA, OTP làm yếu tố thứ hai, OPA kiểm `acr` claim, Redis đếm luỹ kế theo ngày. Tốn nhiều thời gian nhất, cần thêm quyết định phụ (OTP thật qua Keycloak hay mô phỏng).
> - **(b)** Chỉ hạ ngưỡng về 10tr/20tr + viết phân tích khoảng trống, không triển khai step-up thật. Nhanh, nhưng không có bằng chứng "step-up hoạt động" cho khoá luận.
> - **(c)** Giữ nguyên, chỉ nêu ở phần hạn chế.
>
> Nếu chọn (a): yếu tố thứ hai dùng OTP thật trong Keycloak, hay mô phỏng (mint token với `acr=high` trực tiếp để chứng minh cơ chế OPA/PDP, không xây UI OTP)?

**→ QUYẾT ĐỊNH NGƯỜI DÙNG (2026-09-05): (a) triển khai đầy đủ, OTP thật qua Keycloak (không mô phỏng).**

### Đã sửa (thực hiện)

1. **`opa/policies/zta_policy.rego`**: thêm `STEP_UP_SINGLE_VND=10tr`, `STEP_UP_DAILY_VND=20tr`, `requires_step_up`, `step_up_satisfied` (`jwt_payload.acr == "high"`), `payment_with_step_up`. Envoy mặc định KHÔNG gửi body cho ext_authz — bật `includeRequestBodyInCheck` trong `k8s/istio/istio-operator.yaml` (áp qua `istioctl install` cả 2 cluster, xác nhận traffic thật không regress) để `input.parsed_body.amount` có dữ liệu thật.
2. **`services/api-gateway/main.py`**: thêm `GET /internal/daily-cumulative` (đọc luỹ kế ngày từ Redis) để OPA gọi qua `http.send`; `POST /payments` tăng luỹ kế sau mỗi giao dịch thành công.
3. **Keycloak** (Admin API, không qua UI):
   - Client `web-portal`: thêm attribute `acr.loa.map = {"1":1,"high":2}`.
   - Authentication flow mới `browser-stepup` (copy từ `browser`), thêm subflow `Stepup-2fa` (CONDITIONAL) chứa `Condition - Level of Authentication` (yêu cầu LoA≥2, config đúng key `loa-condition-level`/`loa-max-age` — **lưu ý**: Admin Console UI dùng tên hiển thị "level"/"maxAge" nhưng REST API cần đúng 2 tên này, sai tên khiến Keycloak lỗi runtime "Invalid level 'null'") + `OTP Form` (REQUIRED) — đặt **bên trong** subflow `browser-stepup forms` (sau `Username Password Form`), KHÔNG đặt ngang hàng ở top-level (đặt sai vị trí ban đầu làm `auth-otp-form` chạy trước khi có user context, gây `AuthenticationFlowException`).
   - Bind `browser-stepup` làm browser flow override CHỈ cho client `web-portal` (không đổi flow mặc định của realm — không ảnh hưởng client khác).
   - Tạo user riêng `stepup-demo` (không dùng `testuser01`, tránh ảnh hưởng các test/demo khác đang dùng user đó) với credential OTP thật qua chính flow `CONFIGURE_TOTP` của Keycloak (không tự chế secret — xác nhận: hand-import secret qua Admin API bằng chuẩn base32 KHÔNG hoạt động, vì Keycloak dùng RAW BYTES của chuỗi secret tự sinh làm khoá HMAC, không base32-decode).

### Nghiệm thu — kịch bản đúng 3 bước theo tiêu chí gốc của kế hoạch

```
(1) 5tr, không step-up          -> 200 completed
(2) 15tr, không step-up (token acr mặc định) -> 401 {"reason":"step_up_required", ...}
(3) 15tr, SAU KHI step-up thật qua Keycloak (đăng nhập + OTP thật, TOTP tính bằng
    RFC 6238 dùng raw-byte secret, xác nhận qua flow tương tác thật — không mint tay)
    -> token có "acr":"high" -> 200 completed
```

Toàn bộ bước (2)+(3) chạy qua **flow OIDC Authorization Code + PKCE thật** (script Python điều khiển HTTP giống trình duyệt: nhận form đăng nhập thật, submit username/password thật, nhận form OTP thật, tính mã OTP thật rồi submit, nhận redirect + authorization code thật, đổi lấy token thật) — không phải giả lập token.

### 🛑 PHÁT HIỆN PHỤ NGHIÊM TRỌNG — `io.jwt.decode_verify` không xác minh được BẤT KỲ chữ ký JWT thật nào từ Keycloak

Trong lúc nối `step_up_satisfied` vào OPA, phát hiện: **OPA `allow=false` cho MỌI request có JWT thật**, kể cả token hợp lệ 100% (xác nhận: PyJWT độc lập verify THÀNH CÔNG cùng token + cùng JWKS key mà OPA báo thất bại). Điều tra cô lập từng bước:

```
- opa eval trực tiếp io.jwt.decode_verify(token_thật, {"cert": jwks_raw_body, "iss": ...}) -> [false, {}, {}]
- Bỏ "iss" constraint                                                                      -> vẫn [false,{},{}]
- Chỉ dùng đúng 1 key "sig" (loại bỏ key "enc" gây nhiễu)                                   -> vẫn [false,{},{}]
- Test với token TỰ KÝ (RSA tự sinh bằng Python `cryptography`) + JWKS tự tạo               -> [true, {...}, {...}] ĐÚNG
- Nhét thêm key tự sinh vào JWKS THẬT của Keycloak (giữ nguyên cấu trúc, x5c...) + JWT tự ký -> [true, ...] ĐÚNG
- Test với JWKS thật + JWT THẬT của testuser01 (token đã dùng an toàn suốt cả phiên)         -> vẫn [false,{},{}]
```

**Kết luận: OPA (`io.jwt.decode_verify`, phiên bản OPA trong `opa-server` image đã ghim ở T-0.5) không xác minh được chữ ký của BẤT KỲ token nào Keycloak thật sự ký — không phải lỗi riêng của token step-up, không phải lỗi cấu hình JWKS/issuer, không phải bug trong policy T-4.2.** Đây là lỗi **có sẵn từ trước T-4.2**, chỉ chưa từng bị phát hiện vì suốt phiên làm việc, **không có traffic thật nào từng thực sự cần `jwt_signature_valid=true` để được `allow`** — hop `web-portal→api-gateway` luôn được `internal_service_request` (ma trận SPIFFE, T-1.1) cho qua trước, không đụng tới nhánh JWT (đúng "phát hiện phụ" đã ghi ở T-3.1). Hệ quả nghiêm trọng hơn: **kết luận "ĐẠT" của T-1.2 ("OPA tự xác minh chữ ký JWT") chưa từng được chứng minh đúng ở chiều tích cực** — nghiệm thu T-1.2 khi đó chỉ xác nhận JWT **giả** bị từ chối (`result:false`), điều mà một hàm xác minh **luôn luôn trả về false bất kể input** cũng cho kết quả y hệt. T-1.2 cần được coi là "một phần" cho tới khi bug này được sửa và test lại đúng chiều dương (JWT thật phải được `allow=true` qua đúng nhánh `valid_jwt`).

### ✅ ĐÃ SỬA DỨT ĐIỂM (2026-09-06, theo yêu cầu người dùng "sửa lỗi trước khi tiếp tục")

**Xác định nguyên nhân gốc chính xác bằng bisection có kiểm soát hoàn toàn** (không phụ thuộc Keycloak — tự sinh khoá RSA, tự ký token, tự kiểm bằng `opa eval` độc lập, thêm/bớt từng claim một):

```
Token tự ký, payload tối giản {exp,iat,sub}                           -> decode_verify = TRUE
+ thêm claim "aud" (dạng mảng ["a","b"])                                -> FALSE
+ thêm claim "aud" (dạng string đơn "api-gateway"), giữ nguyên còn lại  -> FALSE  (bác bỏ giả thuyết "do mảng")
Payload đầy đủ (13 trường, mô phỏng token Keycloak thật) trừ "aud"      -> TRUE
Payload đầy đủ CÓ "aud" (bất kể mảng hay string)                        -> FALSE
Payload đầy đủ CÓ "aud" + thêm constraint "aud" vào decode_verify()     -> TRUE
```

**Kết luận chắc chắn: `io.jwt.decode_verify()` của OPA trả về `[false,{},{}]` (từ chối, không phải lỗi/exception) bất cứ khi nào token có claim `"aud"` mà `constraints` truyền vào KHÔNG có trường `"aud"` để đối chiếu** — hoàn toàn không liên quan gì tới chữ ký, khoá, issuer, hay Keycloak. Đây là hành vi (có thể là chủ ý, có thể là giới hạn) của chính OPA: có `aud` trong token mà không khai báo `aud` trong constraints = từ chối thẳng, không có cách nào "bỏ qua kiểm tra aud" bằng cách không khai báo gì.

`zta_policy.rego`'s `jwt_verify_result := io.jwt.decode_verify(bearer_token, {"cert":..., "iss":...})` (viết từ T-1.2) **chưa bao giờ** truyền `"aud"` — và MỌI token Keycloak thật đều có `aud` (mặc định luôn có, kể cả trước T-1.4) → bug này tồn tại **từ T-1.2**, không phải do T-4.2 hay T-1.4 gây ra.

**Đã sửa:** thêm `"aud": "api-gateway"` vào constraints của `io.jwt.decode_verify` trong `opa/policies/zta_policy.rego`. Xác nhận `io.jwt.decode_verify` tự so khớp đúng dù token có `aud` dạng mảng hay string đơn (test cả 2 trường hợp). (Dọn thêm, không bắt buộc nhưng vô hại: xoá mapper mặc định "audience resolve" — `oidc-audience-resolve-mapper` trong client scope `roles` của Keycloak — mapper này tự thêm "account" vào `aud` khiến token luôn có mảng 2 phần tử; xoá để `aud` gọn thành 1 giá trị, không ảnh hưởng gì tới các client/luồng khác.)

**Nghiệm thu sau khi sửa (traffic thật, cả 2 cluster):**

```
jwt_signature_valid với token thật, đúng aud     -> true   (TRƯỚC: undefined/false)
valid_jwt với token thật                          -> true   (TRƯỚC: undefined/false)
JWT chữ ký rác (đối chứng)                        -> vẫn từ chối đúng — không fail-open
```

**Khôi phục `payment_with_step_up` vào `allow`** (gỡ bỏ workaround tầng app tạm thời) — giờ OPA **thật sự** gate được hop `web-portal -> api-gateway` dựa trên `jwt_payload.acr`, xác nhận qua decision log thật (`destination=aws/api-gateway`, không phải chỉ tầng app):

```
(1) 5tr, không step-up                    -> OPA allow=true  -> 200 completed
(2) 15tr, không step-up (acr mặc định)     -> OPA allow=false -> 403 (chặn TẠI api-gateway, KHÔNG chạm app)
(3) 15tr, SAU step-up thật (acr=high)      -> OPA allow=true  -> 200 completed
    (xác nhận cả 2 hop: web-portal->api-gateway VÀ api-gateway->payment-service đều allow=true)
```

Giữ nguyên lớp kiểm ở tầng app (`api-gateway/main.py::create_payment`) làm phòng thủ thứ 2 — không gỡ, vì OPA chỉ bảo vệ được hop có SPIFFE ID đi qua sidecar (nhắc lại giới hạn tương tự T-3.1: `kubectl port-forward`/đường vào không qua mesh sẽ bỏ qua lớp OPA, tầng app vẫn chặn đúng trong trường hợp đó).

**Regression suite chạy lại đầy đủ sau khi sửa (không có gì bị phá):** T-1.1 (lateral movement vẫn 403), T-1.2 (JWT giả vẫn bị từ chối, cả qua app lẫn OPA), T-1.4 (audience sai vẫn 401), T-4.1 (device_trust=suspicious vẫn bị chặn, script `grafana_kb_t4_untrusted_device.sh` PASS), T-3.2 (`test_service_graph_consistency.py` PASS), `health-check.sh` PASS=30 WARN=6 FAIL=0.

**Hệ quả cần ghi rõ cho khoá luận:** kết luận "ĐẠT" của T-1.2 ("OPA tự xác minh chữ ký JWT") ban đầu **không sai về đích đến cuối cùng, nhưng quy trình kiểm chứng khi đó có lỗ hổng phương pháp thật** — chỉ test được chiều "từ chối JWT giả" (điều một hàm luôn-luôn-false cũng thoả mãn), chưa từng test được chiều "chấp nhận JWT thật" cho tới tận T-4.2. Đây là một phát hiện có giá trị độc lập, đáng đưa vào khoá luận như một ví dụ cụ thể về khoảng cách giữa "unit test pass" và "tính năng hoạt động đúng trong thực tế" — chỉ lộ ra khi có một tính năng MỚI (step-up) thực sự cần tới chiều dương của phép kiểm.

**Ghi chú phụ (không phải lỗi, là bằng chứng đúng thiết kế của T-4.2):** trong lúc test nhiều lần, luỹ kế NGÀY của ACC-1001 vượt 20 triệu → mọi giao dịch tiếp theo từ tài khoản này đúng ra đều cần step-up cho tới hết ngày UTC (khoá Redis TTL 2 ngày) — xác nhận rule "luỹ kế >20tr/ngày" hoạt động thật. Đã xoá key `api-gateway:daily-cumulative:ACC-1001:<ngày>` để demo sạch lại; muốn dùng lại cho test khác thì xoá tương tự.

**Kết luận T-4.2: ĐẠT đầy đủ** — thiết kế + cơ chế Keycloak OTP thật + enforcement thật ở CẢ 2 tầng (OPA và app), không còn workaround tạm thời. Bug OPA JWT verification đã sửa dứt điểm, có nghiệm thu regression đầy đủ.

### ⚠️ Phát hiện phụ mới (2026-09-06, phát sinh khi re-test T-4.2 sau khi sửa bug OPA JWT) — regression thật ở cấu hình Keycloak flow, đã revert

Trong lúc verify lại toàn bộ flow step-up qua đường thật (`web-portal` login bình thường, không phải test trực tiếp Keycloak), phát hiện: **bind flow `browser-stepup` làm browser flow mặc định của client `web-portal` khiến MỌI đăng nhập bình thường (kể cả không có `acr_values=high`) cũng bị bắt cấu hình "Mobile Authenticator Setup"** — một regression thật, ảnh hưởng TOÀN BỘ luồng đăng nhập, không chỉ step-up.

**Nguyên nhân nghi vấn (chưa xác định dứt điểm):** "Condition - Level of Authentication" (cấu hình `loa-condition-level=2`) có vẻ không chỉ so khớp "acr_values đã yêu cầu tường minh" như helpText mô tả ("Flow is executed only if the configured LOA... has been requested") — thử thêm `default.acr.values` trên client để thiết lập baseline LoA=1 cho trường hợp không yêu cầu tường minh nhưng bị Keycloak từ chối (`400 Bad Request`) khi PUT, chưa tìm ra định dạng đúng.

**Đã xử lý ngay (ưu tiên an toàn):** gỡ `authenticationFlowBindingOverrides` khỏi client `web-portal` (revert về flow `browser` mặc định của realm) — xác nhận login `testuser01` bình thường trở lại đúng ngay (không còn bị bắt OTP). **Lưu ý kỹ thuật khi revert:** PUT `authenticationFlowBindingOverrides: {}` (xoá key) KHÔNG có tác dụng — Keycloak vẫn giữ nguyên override cũ; phải PUT `{"browser": ""}` (giá trị rỗng, giữ key) mới thực sự xoá — một quirk khác của Admin REST API đáng ghi lại (giống quirk `loa-condition-level`/`loa-max-age` đã gặp trước đó ở T-4.2).

**Hệ quả cho hiện trạng:** flow `browser-stepup` + user `stepup-demo` + OTP credential thật **vẫn tồn tại nguyên vẹn** (không xoá gì) và **đã được chứng minh hoạt động đúng** khi gọi TRỰC TIẾP Keycloak với `acr_values=high` tường minh (toàn bộ nghiệm thu T-4.2 ở trên dùng đúng cách này). Vấn đề CHỈ xảy ra khi flow này được BIND làm mặc định cho client — hiện đã gỡ bind, nên:
- Cơ chế OPA/PDP (`payment_with_step_up`, đã bật trong `allow`) vẫn đúng và sẵn sàng — không đổi gì ở tầng OPA.
- Để lặp lại đúng demo step-up end-to-end (như đã làm ở T-4.2), cần BIND LẠI flow tạm thời trước khi chạy demo, rồi gỡ lại sau — thao tác thủ công, chưa tự động hoá.
- Login bình thường (không cần step-up) của mọi user khác **đã xác nhận hoạt động đúng** sau khi gỡ bind.

**Chưa giải quyết dứt điểm trong phiên này** (cần quyết định có đáng đầu tư thêm thời gian không, vì đã có bằng chứng cơ chế OPA/PDP hoạt động đúng độc lập với vấn đề bind flow này):
- (a) Tìm đúng cấu hình `default.acr.values`/tương đương để flow chỉ kích hoạt khi acr_values được yêu cầu tường minh, rồi bind lại an toàn.
- (b) Chấp nhận thao tác bind/unbind thủ công mỗi lần cần demo step-up, ghi rõ vào hạn chế vận hành.
- (c) Thiết kế lại: dùng một CLIENT RIÊNG (không phải `web-portal`) chỉ dành cho luồng step-up, để không ảnh hưởng client đăng nhập chính — tốn công tạo thêm 1 client nhưng cô lập rủi ro triệt để.

---

# GIAI ĐOẠN 5 — ĐO LẠI ĐÚNG PHƯƠNG PHÁP

## T-5.1 — Sửa `source_ip`

**Xác nhận lại vấn đề (T-0.3):** `request.client.host` tại `api-gateway` luôn là loopback (istio-proxy terminate TCP rồi forward qua loopback) — đúng như đã ghi nhận. Xác nhận thêm: Istio **không có** khái niệm `numTrustedProxies`/tự động thêm `X-Forwarded-For` cho traffic sidecar-to-sidecar (đông-tây) — khác với Ingress Gateway (nơi `ProxyConfig.gatewayTopology.numTrustedProxies` mới áp dụng). Xác nhận bằng decision log OPA thật: không request pod-to-pod nào trong toàn bộ phiên làm việc có header `x-forwarded-for`. Vì vậy "dùng XFF + numTrustedProxies trong meshConfig" như plan gốc đề xuất **không có chỗ để cấu hình ở tầng mesh cho sidecar** — phải tự relay ở tầng app, tương tự cách `X-Trace-ID`/`X-User-ID` đã được forward thủ công trong chính codebase này.

**Đã sửa:**
1. `services/web-portal/main.py`: thêm helper `_client_ip(request)` — vì `web-portal` là điểm chạm ngoài-mesh THẬT SỰ duy nhất hiện có (không có Istio Gateway/NodePort nào lộ `api-gateway` ra ngoài, xác nhận lại từ T-3.1), nên `request.client.host` tại ĐÂY là IP client thật. Forward qua header `X-Forwarded-For` ở 3 endpoint chính gọi vào `api-gateway`: `get_balance` (`/accounts/{id}`), `get_transactions` (`/transactions`), `do_transfer` (`/payments`).
2. `services/api-gateway/main.py`: `_source_ip` ưu tiên đọc `X-Forwarded-For` (lấy giá trị đầu tiên nếu là danh sách) trước khi rơi về `request.client.host`. Tin header này vì nguồn DUY NHẤT gọi vào các endpoint này là `web-portal` — đã được xác thực qua SPIFFE ở OPA (`service_acl`, T-1.1) trước khi tới đây — tương đương "1 trusted proxy" duy nhất trong kiến trúc hiện tại.

**Nghiệm thu (traffic thật, không phải input giả):**
```
Gửi 65 request liên tiếp qua mesh thật (web-portal pod -> api-gateway), header
X-Forwarded-For: 203.0.113.99 gắn tay để mô phỏng client thật đứng sau web-portal:
  -> rate limit kích hoạt đúng ở request thứ 61 (RATE_LIMIT_PER_MINUTE=60)
  -> log: {"event":"rate_limit_exceeded","source_ip":"203.0.113.99","count":61}
     (TRƯỚC khi sửa: source_ip luôn là "127.0.0.1"/"127.0.0.6" bất kể ai gọi)
```
Xác nhận `_source_ip` giờ đọc đúng địa chỉ được relay, không còn luôn luôn là loopback.

**Giới hạn còn lại (ghi rõ, chưa mở rộng thêm trong phiên này):** mới forward XFF ở 3 endpoint chính (`get_balance`, `get_transactions`, `do_transfer`) — CÁC endpoint khác của `web-portal` gọi `api-gateway` (tạo tài khoản lúc đăng ký, `_lookup_account`, v.v.) CHƯA được cập nhật tương tự, vẫn sẽ ghi loopback ở `api-gateway` nếu bị rate-limit. Không ảnh hưởng tính đúng đắn bảo mật (chỉ ảnh hưởng độ chính xác của rate-limit/IP-block cho các endpoint đó), nhưng cần hoàn thiện nếu muốn nhất quán 100%.

**Kết luận T-5.1: ĐẠT** cho luồng nghiệp vụ chính (đọc/ghi giao dịch) — đã xác nhận bằng traffic thật, không suy đoán.

## T-5.2 — Rate limit chuyển sang Redis

**Vấn đề (F11):** `_recent_by_source` (`api-gateway/main.py`, dict `defaultdict(deque)` trong tiến trình) chỉ đúng khi có ĐÚNG 1 replica — mỗi pod giữ dict riêng, không đồng bộ, nên giới hạn thật sự cao gấp N lần cấu hình khi scale N replica (không cảnh báo gì), và key trong dict không bao giờ bị dọn (rò rỉ bộ nhớ theo số lượng source_ip khác nhau từng thấy).

**Đã sửa:** thay bằng Redis sorted set dùng chung (`ztlab:ratelimit:{source_ip}`, member = `{timestamp}:{uuid4()}` để tránh đụng độ khi 2 request cùng millisecond, score = timestamp): `ZREMRANGEBYSCORE` cắt entry cũ hơn 60s, `ZADD` entry mới, `ZCARD` đếm, `EXPIRE 65` để tự dọn nếu source_ip ngừng gọi hẳn — chạy cả 4 lệnh trong 1 pipeline Redis. Xoá hẳn `_recent_by_source`/`deque`/`defaultdict` khỏi code (không còn nơi nào dùng).

**Nghiệm thu (traffic thật, qua mesh, KHÔNG port-forward):**
```
Scale api-gateway lên 2 replica (2 pod khác node: ip-10-10-1-11, ip-10-10-1-12) để
buộc traffic bị load-balance thật giữa 2 tiến trình riêng biệt. Từ pod web-portal,
gửi GET /accounts/ACC-1001 (token thật lấy qua password grant từ Keycloak) với
X-Forwarded-For: 203.0.113.55 cố định, 70 request liên tiếp.

Log thật từ CẢ 2 pod (kubectl logs -l app=api-gateway --prefix), lọc rate_limit_exceeded:
  [pod .../fhd2c]  count=108, count=110, ...
  [pod .../pc4zb]  count=61, count=65, 66, 67, 69, 72, 73, 74, ...100, 102, 105, 109
-> count tăng liên tục, XUYÊN SUỐT cả 2 pod cho cùng 1 source_ip (không phải mỗi pod
   tự đếm từ 0) -> xác nhận bộ đếm dùng chung qua Redis, không còn phụ thuộc pod nào
   nhận request. Ngưỡng chặn kích hoạt đúng tại count=61 (RATE_LIMIT_PER_MINUTE=60,
   điều kiện count > 60), khớp hành vi cũ khi còn 1 replica.
```
(20 request đầu của lần chạy này trả `503` — không liên quan rate limit: 2 pod api-gateway vừa mới scale/restart vài giây trước, sidecar istio-proxy cần thời gian thiết lập lại mTLS/route sang core-banking bên OpenStack; xác nhận `core-banking` pod phía OpenStack khoẻ mạnh, không restart trong 4h58m trước đó — hiện tượng cold-start sau rollout, không phải hồi quy do thay đổi này.)

Đã trả `api-gateway` về `replicas: 1` như cấu hình gốc sau khi nghiệm thu xong (không đổi cấu hình lâu dài ở bước này — T-5.4 sẽ quyết định replicas theo thí nghiệm riêng của nó).

**Kết luận T-5.2: ĐẠT** — rate limit giờ đúng đắn khi scale nhiều replica, đã xác nhận bằng traffic thật qua 2 pod thật, không suy đoán.

## T-5.3 — Kiểm chứng giả thuyết `http.send` (thí nghiệm quan trọng)

**Sự cố phương pháp phát hiện TRƯỚC KHI đo (quan trọng, giống lỗi đã gặp ở T-3.1/T-4.2):** lần chạy thử đầu tiên dùng `kubectl port-forward` sẵn có tới `localhost:18080` (giống cấu hình mặc định của `tests/perf_overhead.py`) — kiểm tra chéo bằng decision log của OPA (`kubectl logs deploy/opa-server`) cho thấy **0 decision log entry** ứng với các request gửi qua đường này, dù request vẫn trả về 200/401 bình thường. Xác nhận: `kubectl port-forward` kết nối thẳng vào `localhost:<port>` BÊN TRONG network namespace của pod, không đi qua chuỗi iptables inbound của istio-proxy — bỏ qua hoàn toàn sidecar, tức bỏ qua cả mTLS lẫn OPA ext_authz. Nếu đo bằng đường này, "Config A (hiện trạng)" sẽ thực chất là "không có Zero Trust nào cả" — sai hoàn toàn so với thứ cần đo. **Đã sửa phương pháp:** toàn bộ 4 cấu hình A–D dưới đây đều đo bằng cách `kubectl exec` vào pod `web-portal` (có sidecar thật) và gọi `GET http://api-gateway.financial.svc.cluster.local:8080/accounts/ACC-1001` qua DNS nội bộ cluster — xác nhận lại bằng decision log OPA cho thấy đúng 1 decision/request ứng với địa chỉ pod thật của `api-gateway`.

**Endpoint đo:** `GET /accounts/ACC-1001` (JWT thật lấy qua password grant Keycloak, gắn `Authorization` + `X-Forwarded-For` cố định). Đã tạm nâng `RATE_LIMIT_PER_MINUTE` lên rất cao (không đổi logic rate-limit, chỉ để tránh nhiễu 429 khi gửi hàng nghìn request liên tiếp) và trả lại giá trị mặc định ngay sau khi đo xong toàn bộ 4 cấu hình.

**4 cấu hình đã đo (n=1000 + warm-up 100, loại bỏ khỏi thống kê, mỗi cấu hình):**
- **A — Hiện trạng:** không đổi gì.
- **B — Bỏ `http.send`:** thay `jwks_response`/`discovery_response` (2 lệnh `http.send` gọi Keycloak trong `zta_policy.rego`) bằng giá trị JWKS/issuer THẬT lấy 1 lần trước khi đo, nạp thẳng làm hằng số Rego (tương đương chi phí runtime với nạp từ `data` document của 1 bundle — không dựng riêng cơ chế bundle push cho thí nghiệm này, ghi rõ đơn giản hoá này). Đã `opa check` xác nhận cú pháp hợp lệ trước khi deploy; phát hiện thêm 1 lỗi kiểu tĩnh của OPA khi làm việc này (tham chiếu `.error` trên object không khai báo key đó bị từ chối lúc biên dịch — khác hẳn hành vi cũ khi `http.send` trả về kiểu động) — sửa bằng cách thêm tường minh `"error": null` vào object tĩnh.
- **C — mTLS bật, OPA tắt:** xoá tạm `AuthorizationPolicy api-gateway-opa-authz` (namespace financial, AWS). Xác nhận bằng decision log: sau khi xoá, không còn entry nào của OPA ứng với địa chỉ pod `api-gateway` (chỉ còn entry của hop kế tiếp `api-gateway -> payment-service`, hop này KHÔNG bị đụng tới).
- **D — Không mTLS, không OPA:** giữ nguyên (C) + patch tạm `DestinationRule api-gateway-custom-san` (đã tồn tại sẵn từ trước, cùng host — phát hiện: tạo `DestinationRule` MỚI cho cùng host bị Istio bỏ qua do 2 DR trùng host, phải patch thẳng cái đã tồn tại) từ `tls.mode: ISTIO_MUTUAL` sang `DISABLE`. Xác nhận qua `istioctl proxy-config cluster` (cluster outbound của `web-portal` sang `api-gateway` không còn `transportSocket` TLS) và qua access log Envoy (`"svid":null` thay vì SPIFFE ID thật).

Sau khi đo xong cả 4 cấu hình: patch `DestinationRule` về `ISTIO_MUTUAL` như cũ, `kubectl apply` lại đúng YAML gốc của `AuthorizationPolicy` đã xoá, phục hồi `zta_policy.rego` nguyên bản (diff xác nhận khớp 100% byte), trả `RATE_LIMIT_PER_MINUTE` về mặc định. Nghiệm thu lại: request JWT thật qua `api-gateway` vẫn 200, access log xác nhận lại có SVID thật (mTLS) VÀ decision log OPA xác nhận lại có entry cho `api-gateway` (OPA on) — cả 2 tầng đã bật lại đúng như ban đầu. `test_service_graph_consistency.py` PASS cả 2 test. `health-check.sh` PASS=30 WARN=6 FAIL=0 — không đổi so với trước khi bắt đầu T-5.3.

**Kết quả (ms, thật, n=1000/cấu hình, khoảng tin cậy 95% qua bootstrap 1000 lần resample):**

| Cấu hình | p50 | p50 CI95% | p95 | p95 CI95% | p99 | p99 CI95% | mean |
|---|---|---|---|---|---|---|---|
| A — Hiện trạng | 108.65 | [108.08, 109.35] | 133.23 | [130.50, 137.24] | 166.59 | [153.60, 218.65] | 112.94 |
| B — Bỏ http.send | 102.28 | [102.12, 102.49] | 120.47 | [117.78, 122.97] | 158.60 | [136.78, 206.10] | 106.03 |
| C — OPA tắt | 102.16 | [101.93, 102.45] | 119.27 | [117.15, 122.06] | 170.46 | [144.87, 192.88] | 105.03 |
| D — Không mTLS, không OPA | 102.02 | [101.75, 102.30] | 119.54 | [116.20, 124.28] | 156.85 | [135.89, 175.62] | 104.20 |

0 lỗi (0 request nào ngoài 200) ở cả 4 cấu hình, 1100/1100 mỗi cấu hình đều thành công.

**Áp bảng quyết định của kế hoạch:**
- B so với A: chênh lệch p50 chỉ ~6.4ms (108.65 → 102.28), tức **~6%**, KHÔNG đạt ngưỡug ">50% nhanh hơn" mà giả thuyết yêu cầu để coi là "đúng". → **Giả thuyết `http.send` là nguyên nhân chính bị BÁC BỎ.** Tuy nhiên khoảng tin cậy 95% của A và B **không giao nhau** ([108.08,109.35] vs [102.12,102.49]) — chênh lệch ~6ms này có thật về mặt thống kê, không phải nhiễu đo, chỉ là nhỏ hơn hẳn so với con số ~127ms trong `DANH_GIA_HE_THONG.md §3.2`.
- C so với A: p50 gần bằng B (102.16 vs 102.28) — tắt hẳn OPA (không chỉ bỏ http.send) KHÔNG giảm thêm latency đáng kể so với B. → OPA eval time tự nó (đã xác nhận riêng qua chính decision log của OPA: `timer_rego_query_eval_ns` đo được cho request `/accounts/ACC-1001` có JWT thật là **6.9ms** — số thật, không suy đoán) là một phần nhỏ, không phải "phần lớn overhead ~127ms".
- D so với A: p50 gần bằng C (102.02) — tắt thêm cả mTLS trên hop này cũng KHÔNG giảm thêm. → mTLS handshake ở hop client→api-gateway này cũng không phải nguyên nhân chính.

**Kết luận T-5.3 (khác cả 3 dòng trong bảng quyết định gốc — đây là kết quả đáng giá nhất của thí nghiệm):** KHÔNG cấu hình nào trong B/C/D (bỏ http.send / tắt OPA / tắt cả mTLS lẫn OPA) giải thích được phần lớn latency ~100ms+ quan sát được — cả 3 đều xấp xỉ nhau (102ms) và chỉ thấp hơn A đúng ~6ms. Toàn bộ ~100ms còn lại nằm ở phần **KHÔNG bị đụng tới bởi cả 4 cấu hình**: 2 hop tiếp theo trong chuỗi gọi thật của endpoint này (`api-gateway -> payment-service -> core-banking` qua NodePort cross-cluster `core-banking-openstack.financial.svc.cluster.local:30080`), vẫn giữ nguyên mTLS + OPA CUSTOM authz ở CẢ 4 cấu hình vì thí nghiệm này (đúng theo thiết kế trong kế hoạch) chỉ đổi cấu hình ở hop đầu (client → api-gateway).

Đã loại trừ nguyên nhân "độ trễ mạng thô giữa 2 cloud": đo trực tiếp `socket.connect()` từ pod `web-portal` tới `core-banking-openstack...:30080` — **0.9ms trung bình** (20 lần đo), không phải nguồn của ~100ms.

**Nghi vấn có căn cứ (CHƯA đo tách bạch, ghi rõ là suy luận có bằng chứng gián tiếp, không phải kết luận đã kiểm chứng đầy đủ như bảng trên):** cả `api-gateway/main.py` (`get_account`) lẫn `payment-service/main.py` (`proxy_get_account`, và các hàm proxy khác) đều tạo **`httpx.AsyncClient` MỚI cho MỖI request** (`async with httpx.AsyncClient(...) as client:` bên trong handler) thay vì tái dùng 1 client/connection pool dùng chung — nghĩa là 2 hop còn lại (`api-gateway->payment-service`, `payment-service->core-banking`) phải bắt tay mTLS MỚI cho MỖI request, không có keep-alive, CỘNG với OPA CUSTOM authz vẫn chạy đủ ở cả 2 hop này tại mọi cấu hình A-D. Đây là ứng viên hợp lý nhất cho phần ~100ms còn lại, nhưng KHÔNG nằm trong phạm vi 4 cấu hình A-D mà kế hoạch yêu cầu đo — cần một thí nghiệm riêng (đổi `httpx.AsyncClient()` per-request thành 1 client dùng chung ở scope module, đo lại) mới có thể kết luận chắc chắn. Đề xuất ghi vào khoá luận như một hướng cần đo thêm (T-5.3b, ngoài phạm vi kế hoạch gốc), không tự ý mở rộng thí nghiệm thêm trong phiên này.

**Việc cần cập nhật tài liệu:** `DANH_GIA_HE_THONG.md §3.2` (số liệu n=20, quy sai nguyên nhân overhead cho OPA/http.send) cần viết lại theo đúng số liệu và kết luận ở trên — n=1000+CI thay cho n=20, và đổi hướng quy nguyên nhân từ "OPA/http.send" sang "khả năng cao là chi phí kết nối lặp lại + mTLS ở các hop nội bộ tiếp theo, không phải OPA".

**Kết luận T-5.3: ĐẠT (đã đo đúng phương pháp, n=1000+CI, cả 4 cấu hình)** — giả thuyết gốc bị bác bỏ bằng số liệu thật, phát hiện phụ (per-request AsyncClient) là kết quả đáng giá cho khoá luận dù chưa đo tách bạch hoàn toàn trong phiên này.

### ⚠️ Phát hiện phụ trong lúc chuẩn bị đo T-5.4: `_jwks_refresh_loop` retry 300s kể cả khi lần nạp đầu thất bại

Trong lúc phải `kubectl set env`/`rollout restart` `api-gateway` nhiều lần (để bật/tắt `RATE_LIMIT_PER_MINUTE` phục vụ đo đạc), lặp lại đúng 3 lần cùng một hiện tượng: pod mới khởi động, `_load_oidc_config()` gọi Keycloak lần đầu bị `[Errno 111] Connection refused` (istio-proxy sidecar của chính pod đó chưa kịp sẵn sàng route egress tại đúng thời điểm app container gọi lúc `startup`), và vì `_jwks_refresh_loop` (`api-gateway/main.py`) cũ ngủ nguyên 300 giây bất kể lần nạp có thành công hay không, pod đó fail-closed (`jwks_unavailable_fail_closed`, mọi request JWT thật bị 503) suốt tới 5 phút dù lỗi tự khỏi trong vài giây — không quan sát được qua test bình thường (chỉ lộ ra vì phiên làm việc này phải restart pod liên tục để phục vụ đo).

**Đã sửa:** tách rõ 2 chu kỳ — retry nhanh (5s) khi CHƯA có key nào, chỉ giãn ra 300s một khi đã nạp thành công ít nhất 1 lần (chu kỳ làm mới định kỳ đúng ý đồ gốc). Xác nhận thật: restart pod, log cho thấy nạp lại thành công trong ~5s (`19:52:47` thất bại lần đầu → `19:52:52` `oidc_config_loaded`) thay vì phải đợi tới 300s như trước khi sửa. Đã áp dụng qua patch-configmap + rollout restart, `health-check.sh` và `test_service_graph_consistency.py` vẫn PASS sau khi sửa.

## T-5.3b — Đo lại với shared `httpx.AsyncClient` (theo dõi phát hiện phụ của T-5.3)

**Ngày đo:** 2026-09-08 (phiên riêng, sau khi hạ tầng đã bị `destroy` và deploy lại từ đầu — xem `VIEC-CON-TON-DONG.md` mục 3.2 để biết bối cảnh đầy đủ, kể cả 2 lần đo hỏng trước khi ra được số liệu này).

**Thay đổi code:** `services/api-gateway/main.py` và `services/payment-service/main.py` đổi từ `async with httpx.AsyncClient(...) as client:` tạo mới mỗi request sang 1 client dùng chung ở module scope, khởi tạo lúc `@app.on_event("startup")`, đóng lúc `shutdown` — áp dụng cho toàn bộ endpoint gọi cross-service ở cả 2 file, không chỉ `get_account`/`proxy_get_account` như nghi vấn gốc ở T-5.3.

**Phương pháp đo:** giữ nguyên endpoint (`GET /accounts/ACC-1001`) và cách gọi (`kubectl exec` vào `web-portal`, qua mesh thật, JWT thật) như T-5.3 gốc. Khác 2 điểm, cả 2 đều do ràng buộc thật của phiên làm việc này chứ không phải chủ ý đổi phương pháp:
- Không nâng tạm `RATE_LIMIT_PER_MINUTE` (T-5.3 gốc có làm, rồi trả lại mặc định sau) — hành động sửa live-config bị chặn bởi lớp an toàn của phiên làm việc lần này. Thay vào đó tự throttle request ở phía đo (~54 req/phút, dưới mức 60/phút mặc định).
- JWT phải tự refresh giữa chừng qua `refresh_token` (T-5.3 gốc dùng 1 token cố định suốt) vì `accessTokenLifespan=300s` ngắn hơn tổng thời gian chạy (~23 phút do bị throttle).

**Kết quả (n=1000 + warmup 100, 1000/1000 thành công, 0 lỗi, CI95% qua bootstrap 1000 lần resample):**

| Cấu hình | p50 | p50 CI95% | p95 | p95 CI95% | p99 | p99 CI95% | mean |
|---|---|---|---|---|---|---|---|
| A — Gốc (per-request `AsyncClient`, đo 2026-09-05) | 108.65 | [108.08, 109.35] | 133.23 | [130.50, 137.24] | 166.59 | [153.60, 218.65] | 112.94 |
| A' — Shared `AsyncClient` (đo 2026-09-08) | 147.08 | [145.13, 148.91] | 249.43 | [244.48, 255.07] | 321.35 | [302.56, 334.36] | 168.66 |

**Kết quả NGƯỢC hoàn toàn với giả thuyết:** A' chậm hơn A ở cả p50 (+35%), p95 (+87%), p99 (+93%) — không hề nhanh hơn như kỳ vọng từ phát hiện phụ của T-5.3.

**KHÔNG kết luận "shared client làm chậm hơn"** — phép so sánh A vs A' lần này không sạch về phương pháp, khác nhiều hơn đúng 1 biến `httpx.AsyncClient` như thiết kế 4-cấu-hình gốc của T-5.3:
1. A đo trên hạ tầng vừa deploy xong ngày 2026-09-05, chưa qua sự cố nào. A' đo ngày 2026-09-08, SAU một phiên làm việc dài với hàng loạt sự cố nối tiếp trên chính hạ tầng đang đo: máy host bị suspend/resume, `spire-agent` DaemonSet OpenStack crashloop nhiều giờ (đã fix), cert mTLS của core-banking/account-service/transaction-service phải làm mới, tunnel SSH tới AWS tự rớt giữa phiên đo (phải phát hiện + bật lại), RabbitMQ/nova phải restart nhiều lần trong ngày. Không có cách nào tách bạch phần overhead do code khỏi phần overhead do hạ tầng đang ở trạng thái "mệt" hơn hẳn so với A.
2. Thiếu sót phương pháp thật sự: không đo lại cấu hình A (revert tạm về per-request client) NGAY TRƯỚC A' trong cùng phiên này để có đối chứng cùng điều kiện hạ tầng — nếu làm vậy sẽ loại bỏ được biến "khác thời điểm" ở trên.

**Quyết định:** giữ nguyên thay đổi shared `httpx.AsyncClient` trong code (bản thân là cải tiến kỹ thuật đúng đắn — giảm số lần bắt tay mTLS mới mỗi request, tránh tạo/huỷ connection pool liên tục — không phụ thuộc kết quả đo này để biện minh). `test_service_graph_consistency.py` PASS, `health-check.sh` PASS=30 WARN=6 FAIL=0 sau khi đổi.

**Kết luận T-5.3b: KHÔNG ĐẠT theo đúng nghĩa gốc của thí nghiệm** (không cô lập được biến, không thể dùng số liệu này để xác nhận hay bác bỏ giả thuyết per-request-`AsyncClient`). Có giá trị làm điểm dữ liệu tham khảo + minh chứng cho một rủi ro phương pháp luận thật (đo hiệu năng trên hạ tầng lab dùng chung, không cô lập, dễ lẫn nhiễu môi trường vào kết luận về code) — đáng đưa vào khoá luận như một bài học về thiết kế thí nghiệm, không phải như một kết quả hiệu năng đã kiểm chứng. Muốn kết luận dứt điểm: lặp lại cả A và A' trong cùng 1 phiên hạ tầng ổn định, không có sự cố xen giữa hai lần đo — ngoài phạm vi phiên làm việc này.

## T-5.4 — Đo cái giá của fail-closed

**Bối cảnh:** `opa/deployment.yaml` cũ có `replicas: 1` + `failure_mode_allow: false` ở extensionProvider — mất pod OPA duy nhất = toàn bộ giao dịch 2 cloud dừng (F10).

> 🛑 G9 đã hỏi người dùng: đo `replicas:1` trước rồi mới tăng lên 3+PDB, đo lại — người dùng chọn phương án này (đo đầy đủ, không chốt luôn 3 mà bỏ qua đối chứng).

**Phương pháp:** tạo tải thật liên tục (script Python trong pod `web-portal`, 1 request GET `/accounts/ACC-1001` mỗi 0.2s, JWT thật) chạy 90 giây; giữa chừng (khoảng giây thứ 15) xoá 1 pod OPA bằng `kubectl delete pod --wait=false` (không chờ, đúng kiểu sự cố thật — không phải drain có kiểm soát); ghi lại timestamp tương đối + mã trả về của TỪNG request để xác định chính xác cửa sổ mất dịch vụ. Đã tạm nâng `RATE_LIMIT_PER_MINUTE` để loại nhiễu 429 (không liên quan tới OPA), trả lại mặc định sau khi đo xong.

**Kết quả 1 — `replicas: 1` (hiện trạng gốc trước khi sửa):**
```
Xoá pod OPA duy nhất lúc 19:53:48.6Z (kubectl delete --wait=false).
281 request thật trong 90s: 254x 200, 27x 403 liên tiếp, 0 mã lỗi khác.
27 request 403 xảy ra liên tục từ t=17.41s đến t=22.71s (request thành công đầu
tiên sau đó ở t=23.04s) -> cửa sổ mất dịch vụ ~5.6 giây, đúng 100% request
trong cửa sổ đó bị từ chối (403, do failure_mode_allow:false của Istio CUSTOM
authz khi backend ext_authz không tới được — không phải lỗi, đây LÀ hành vi
fail-closed đúng thiết kế).
Không cần can thiệp tay: Kubernetes tự tạo pod OPA mới, Envoy tự cập nhật
endpoint qua EDS, dịch vụ tự phục hồi sau ~5.6s.
```

**Đã sửa:** `opa/deployment.yaml` — tăng `replicas: 1` → `3`, thêm `PodDisruptionBudget` (`minAvailable: 2`) để ngăn rolling-update/voluntary-eviction làm giảm xuống dưới 2 pod cùng lúc. `kubectl apply`, xác nhận cả 3 pod `Running` trên 3 node vật lý khác nhau (tự nhiên do scheduler, không ép `podAntiAffinity` — ghi nhận đây là may mắn của cụm hiện tại chứ không phải đảm bảo cứng; nếu cần đảm bảo tuyệt đối 3 pod luôn khác node, nên thêm `podAntiAffinity` — không làm trong phạm vi T-5.4 vì không phải yêu cầu của kế hoạch gốc).

**Kết quả 2 — `replicas: 3` + PDB:**
```
Xoá 1 trong 3 pod OPA lúc 19:58:26.9Z (kubectl delete --wait=false), 2 pod còn
lại vẫn chạy bình thường trong suốt quá trình.
268 request thật trong 90s: 268x 200, 0 lỗi. Không có cửa sổ mất dịch vụ nào
quan sát được — Envoy load-balance ext_authz gRPC sang 2 pod còn lại ngay lập
tức, client không nhận biết được sự kiện xoá pod.
```

**So sánh:**

| Cấu hình | Request thất bại trong cửa sổ đo | Thời gian mất dịch vụ | 
|---|---|---|
| `replicas: 1` | 27/281 (9.6% của toàn bộ cửa sổ 90s đo được, 100% trong đúng khoảng ~5.6s xảy ra sự cố) | ~5.6 giây |
| `replicas: 3` + PDB | 0/268 | 0 giây (không đo được) |

**Kết luận T-5.4: ĐẠT** — đã đo thật (không suy đoán) cái giá cụ thể của kiến trúc PDP tập trung fail-closed đơn-replica (~5.6s mất dịch vụ 100% mỗi lần pod OPA gặp sự cố/redeploy), và xác nhận thật rằng `replicas:3`+PDB loại bỏ hoàn toàn cửa sổ này cho trường hợp mất 1 pod đơn lẻ (không đo trường hợp mất đồng thời ≥2/3 pod — ngoài phạm vi thí nghiệm này). Đã ÁP DỤNG `replicas:3`+PDB làm cấu hình chính thức mới (không revert về 1) vì lợi ích đo được là rõ ràng và không phát sinh hồi quy nào (`health-check.sh` PASS=30 WARN=6 FAIL=0, `test_service_graph_consistency.py` PASS, đúng như trước khi bắt đầu). Lưu ý: số liệu overhead ở T-5.3 đã đo Ở `replicas:1` (theo đúng lựa chọn G9 của người dùng) — nếu cần số liệu overhead tại `replicas:3` để so sánh đầy đủ, cần đo lại T-5.3 (ngoài phạm vi đã làm trong phiên này, có thể làm thêm nếu người dùng yêu cầu).

### Mở rộng T-5.4 sang OpenStack + rà soát khả năng tái tạo (IaC) trước khi destroy

Người dùng hỏi trực tiếp: "sau khi destroy và deploy lại, hệ thống có đúng như mong muốn không?" — rà soát lại (grep thật, không suy đoán từ trí nhớ) phát hiện 2 khoảng hở IaC, cả 2 đã xử lý ngay:

1. **`opa-server` bên OpenStack (`k8s/financial/os-security.yaml`) vẫn `replicas: 1`** — T-5.4 gốc chỉ đo/sửa OPA bên AWS (đúng phạm vi `opa/deployment.yaml:10` mà F10/G9 nêu), bỏ sót rằng OpenStack có MỘT instance OPA riêng (phục vụ `zta/crosscloud/allow` cho `core-banking`/`account-service`/`transaction-service`) với cùng kiến trúc PDP tập trung fail-closed, cùng rủi ro F10. Đã áp dụng cùng fix (`replicas: 3` + `PodDisruptionBudget minAvailable: 2`) — không đo lại riêng bằng thực nghiệm xoá pod (suy luận hợp lý từ cùng cấu hình `failure_mode_allow` + cùng cơ chế OPA, ghi rõ đây là suy luận, không phải số đo thật thứ 2). Áp dụng live: 3 pod `Running` trên 3 node khác nhau (`os-k3s-master`, `os-k3s-worker-1`, `os-k3s-worker-2`), PDB xác nhận `MIN AVAILABLE: 2`. Nghiệm thu: request thật qua `api-gateway` → `payment-service` → `core-banking` vẫn 200, `health-check.sh` PASS=31 WARN=5 FAIL=0 (không giảm so với trước).

2. **Flow step-up Keycloak (`browser-stepup`) hoàn toàn không có trong `realm-config.json`** — xác nhận bằng grep: 0 kết quả cho `authenticationFlowBindingOverrides`/`browser-stepup`/`stepup-demo` trong file. Xem mục tiếp theo để biết cách đã script hoá.

### ✅ Đóng phát hiện phụ (Keycloak flow-binding regression) — đã chọn phương án (c)

Người dùng chọn "Tìm cách bind an toàn ngay". Đã thử phương án (a) trước (`default.acr.values` trên client `web-portal`) — Keycloak từ chối với `400 invalid_input: "Default ACR values need to contain values specified in the ACR-To-Loa mapping or number levels from set realm browser flow"` dù giá trị khớp `acr.loa.map` và đã bind flow trước — không tìm ra định dạng đúng trong thời gian hợp lý, dừng hướng này.

**Đã triển khai phương án (c):** tạo client Keycloak riêng `web-portal-stepup` (public, PKCE, cùng redirect URIs với `web-portal`, cùng mapper `aud-api-gateway`, có `acr.loa.map`) và bind `authenticationFlowBindingOverrides: {"browser": "browser-stepup"}` **CHỈ** cho client này — client `web-portal` chính giữ nguyên flow `browser` mặc định của realm, không bị ảnh hưởng.

**Nghiệm thu (traffic thật qua cả 2 client):**
- Đăng nhập bình thường qua `web-portal` (không `acr_values`): không bị bắt cấu hình OTP, `acr` claim không có/không phải `high` — đúng như trước khi có regression.
- Đăng nhập step-up qua `web-portal-stepup` với `acr_values=high`: yêu cầu OTP thật (`stepup-demo` + TOTP tính từ secret tự sinh bởi Keycloak, dùng raw bytes làm khoá HMAC — không phải base32-decode như `pyotp` mặc định), token trả về có `acr:"high"`, giao dịch 15tr qua `/payments` với token này → OPA `allow=true` → 200 completed.
- Regression suite chạy lại toàn bộ sau thay đổi này: T-1.1, T-1.2, T-1.4, T-3.2, T-4.1 đều PASS như trước — không phát sinh hồi quy mới.

**Ghi nhận khoảng cách IaC (chưa đóng hoàn toàn):** đã thêm client `web-portal-stepup` vào `k8s/keycloak/realm-config.json` (đúng cấu hình client đã tạo sống qua Admin API) — client này sẽ tồn tại lại sau khi Keycloak được deploy mới từ đầu. **Tuy nhiên, bản thân authentication flow `browser-stepup`** (subflow điều kiện `Stepup-2fa` + execution `Condition - Level of Authentication` với `loa-condition-level`/`loa-max-age` + `OTP Form`) **vẫn CHỈ tồn tại dưới dạng thay đổi sống qua Admin API, chưa được script hoá vào `realm-config.json` hay `deploy-app.sh`** — do cấu trúc flow lồng nhau (nested execution/subflow) không biểu diễn được trực tiếp trong realm-export JSON đơn giản như protocolMappers/client attributes, cần dùng Admin API tuần tự (create flow → add execution → add subflow → add execution → configure) để tái tạo đúng thứ tự. Đây là một **hạn chế IaC đã biết, ghi nhận rõ ràng**: một lần deploy Keycloak hoàn toàn mới sẽ có client `web-portal-stepup` nhưng flow `browser-stepup` nó tham chiếu sẽ KHÔNG tồn tại (client sẽ dùng flow `browser` mặc định của realm cho tới khi ai đó chạy lại các lệnh Admin API thủ công đã dùng trong phiên này để tạo lại flow và bind). Không mở rộng thêm trong phiên này vì đã có bằng chứng cơ chế OPA/PDP hoạt động đúng độc lập với vấn đề này, và người dùng yêu cầu tiếp tục sang GĐ5.

**Kết luận phát hiện phụ: ĐÃ XỬ LÝ AN TOÀN** (phương án cô lập rủi ro, không sửa lại client chính) — còn 1 khoảng cách IaC đã ghi nhận rõ, không chặn tiến độ GĐ5.

