# VIỆC CÒN TỒN ĐỌNG — cần làm ở lần deploy tiếp theo

> Ngày ghi: 2026-09-05/06. Bối cảnh: hạ tầng (AWS + OpenStack VM) đã bị `destroy`
> ngay sau khi ghi file này — mọi thứ dưới đây giả định bắt đầu lại từ
> `scripts/deploy-security-stack.sh` + `scripts/deploy-app.sh` chạy trên hạ tầng
> MỚI hoàn toàn (Postgres/Keycloak/Redis mới tinh, không còn state cũ).
> File code/YAML/rego trong repo (local disk) KHÔNG bị mất — chỉ hạ tầng cloud bị xoá.

Xem `KE-HOACH-SUA-HE-THONG.md` (kế hoạch gốc) và `KET-QUA-KIEM-TRA.md` (log đầy đủ,
có lệnh + output thật cho mọi mục GĐ0–GĐ5) để biết chi tiết/bối cảnh của từng việc.
GĐ0–GĐ5 của kế hoạch gốc đã **ĐẠT toàn bộ** — các việc dưới đây là phần phát sinh
thêm trong lúc làm, chưa kịp đóng trước khi destroy.

---

## 1. [ĐÃ XONG 2026-09-08] Script hoá flow step-up Keycloak (`browser-stepup`)

**Cập nhật 2026-09-08:** đã tái tạo lại flow `browser-stepup` trên hạ tầng mới
(sau destroy + deploy lại) bằng đúng các bước Admin API dưới đây, và đã thêm
hàm idempotent `deploy_stepup_flow()` vào `scripts/deploy-app.sh` (gọi ngay sau
`deploy_audience_mapper` trong `main()`) — không cần làm tay nữa từ lần deploy
sau. Đã verify: chạy hàm 2 lần liên tiếp đều idempotent đúng (lần 2 skip toàn
bộ), cấu trúc flow qua Admin API khớp 100% cây mục tiêu bên dưới,
`web-portal-stepup` được bind, `web-portal` xác nhận KHÔNG bị đụng tới
(`authenticationFlowBindingOverrides` rỗng). Đã chạy lại
`tests/test_service_graph_consistency.py` (2/2 PASS) và `scripts/health-check.sh`
(PASS=30 WARN=6 FAIL=0, khớp đúng baseline đã ghi ở cuối mục này).

**QUIRK MỚI phát hiện khi làm lại (không có trong ghi chú gốc — Keycloak
24.0.3, có thể do khác lần gọi trước hay đúng là bug của bản này):** endpoint
`POST .../executions/flow` với body `{"name": "Stepup-2fa", ...}` **KHÔNG**
set alias của flow con vừa tạo — flow tạo ra có `alias: null`, khiến mọi lệnh
gọi tiếp theo tham chiếu bằng alias (`/authentication/flows/Stepup-2fa/...`)
bị lỗi `400 Parent flow doesn't exist`. Cách sửa: `GET` flow con vừa tạo qua
`flowId` (lấy từ execution cha, field `flowId`), rồi `PUT` trực tiếp
`/authentication/flows/{id}` với `alias` set tường minh trước khi làm tiếp
bước 4-5. Đã cập nhật cả script `deploy_stepup_flow()` lẫn phần hướng dẫn thủ
công dưới đây để phản ánh đúng fix này.

**CÒN LẠI — không thể tự động hoá, cần làm tay 1 lần (per doc gốc: không được
tự chế `secretData`, phải qua QR thật):** user `stepup-demo` đã được tạo sẵn
(script tự tạo, `requiredActions: CONFIGURE_TOTP`, password tạm
`StepupDemo123!`) nhưng CHƯA enroll OTP thật — cần đăng nhập 1 lần qua trình
duyệt thật tại `$KC_URL/realms/ztlab/account` để Keycloak sinh QR + secret
thật, sau đó credential này persist trong Postgres (không mất khi redeploy
script, chỉ mất nếu destroy hạ tầng). Sau khi enroll xong, chạy nốt 4 mục
nghiệm thu còn lại trong checklist cuối mục này (login thường không bị OTP,
login stepup có OTP + acr=high, giao dịch >10tr bị chặn khi chưa step-up,
thành công sau step-up).

---

## 1cũ (giữ nguyên để tham khảo cấu trúc/lệnh gốc — ƯU TIÊN CAO — Script hoá flow step-up Keycloak (`browser-stepup`))

**Vấn đề:** client `web-portal-stepup` đã có trong `k8s/keycloak/realm-config.json`
(sẽ tự tạo lại đúng khi deploy mới), nhưng **authentication flow `browser-stepup`
mà client này cần lại KHÔNG có trong file** — nó chỉ được tạo bằng tay qua Admin
API ở phiên làm việc trước, và hạ tầng chứa nó đã bị destroy. Nếu deploy lại ngay
bây giờ, tính năng step-up (T-4.2: OTP bắt buộc khi giao dịch >10tr/lần hoặc
>20tr/ngày) sẽ **không hoạt động** — client `web-portal-stepup` tồn tại nhưng
không có flow để bind, sẽ rơi về flow `browser` mặc định (không có OTP).

**Cấu trúc CHÍNH XÁC cần tái tạo** (đã lấy trực tiếp từ Keycloak thật qua Admin
API trước khi destroy, KHÔNG phải nhớ lại/đoán):

```
Flow "browser-stepup" (topLevel, providerId basic-flow) = bản copy của flow
built-in "browser", CỘNG THÊM 1 subflow con:

Level 0 (trực tiếp trong "browser-stepup"):
  - Cookie                          (ALTERNATIVE, auth-cookie)
  - Kerberos                        (DISABLED,    auth-spnego)
  - Identity Provider Redirector    (ALTERNATIVE, identity-provider-redirector)
  - "browser-stepup forms"          (ALTERNATIVE, subflow) ──┐
                                                              │
Level 1 (trong subflow "browser-stepup forms"):              │
  - Username Password Form          (REQUIRED, auth-username-password-form)
  - "browser-stepup Browser -       (CONDITIONAL, subflow — giữ nguyên từ
     Conditional OTP"                bản copy gốc, không đổi gì)
      └─ Level 2: Condition - user configured (REQUIRED, conditional-user-configured)
      └─ Level 2: OTP Form                     (REQUIRED, auth-otp-form)
  - "Stepup-2fa"                    (CONDITIONAL, subflow MỚI — đây là phần
     mô tả: "Step-up: OTP khi         thêm riêng cho step-up, phải tự tạo)
     LoA >= 2 (acr=high)"
      └─ Level 2: "Condition - Level of Authentication"
            providerId: conditional-level-of-authentication
            alias: stepup-loa-2
            requirement: REQUIRED
            config: {"loa-condition-level": "2", "loa-max-age": "36000"}
      └─ Level 2: OTP Form           (REQUIRED, auth-otp-form)
```

**Cách tạo lại bằng Admin API (đã kiểm chứng từng bước hoạt động thật trên Keycloak
24.0.3, xem `KET-QUA-KIEM-TRA.md` phần cuối cùng để biết log kiểm chứng):**

```bash
KC_URL=http://localhost:8180   # hoặc URL Keycloak thật sau khi deploy
REALM=ztlab
ADMIN_TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=<KEYCLOAK_ADMIN_PASSWORD>" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# 1. Copy flow "browser" -> "browser-stepup" (copy cả cây, kể cả "browser-stepup forms"
#    và "browser-stepup Browser - Conditional OTP")
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/browser/copy" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"newName":"browser-stepup"}'

# 2. Thêm subflow "Stepup-2fa" làm con của "browser-stepup forms"
#    LƯU Ý: dùng đúng tên subflow con ("browser-stepup forms"), KHÔNG phải tên
#    flow cha ("browser-stepup") — nếu thêm nhầm vào flow cha, subflow sẽ nằm
#    sai level (level 0 thay vì level 1), không đúng cấu trúc ở trên.
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/browser-stepup%20forms/executions/flow" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Stepup-2fa","description":"Step-up: OTP khi LoA >= 2 (acr=high)","provider":"basic-flow","type":"basic-flow"}'

# 3. Tìm id của execution "Stepup-2fa" vừa tạo (level 1, trong danh sách executions
#    của "browser-stepup"), rồi PUT để đổi requirement từ DISABLED -> CONDITIONAL
curl -s "$KC_URL/admin/realms/$REALM/authentication/flows/browser-stepup/executions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool
# tìm entry có displayName rỗng/None, level=1, providerId=None, flowId=<uuid mới>
# rồi:
curl -s -X PUT "$KC_URL/admin/realms/$REALM/authentication/flows/browser-stepup%20forms/executions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"id":"<execution_id_cua_Stepup-2fa>","requirement":"CONDITIONAL"}'

# 4. Thêm 2 execution con vào bên trong "Stepup-2fa" (dùng flow alias "Stepup-2fa"
#    trực tiếp — vì đây là tên DUY NHẤT trong realm lúc này, không trùng ai)
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/Stepup-2fa/executions/execution" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"provider":"conditional-level-of-authentication"}'
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/flows/Stepup-2fa/executions/execution" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"provider":"auth-otp-form"}'

# 5. Cấu hình "Condition - Level of Authentication" (loa-condition-level=2, loa-max-age=36000)
#    Lấy execution id của nó từ bước 4 (providerId=conditional-level-of-authentication),
#    rồi POST config:
curl -s -X POST "$KC_URL/admin/realms/$REALM/authentication/executions/<execution_id>/config" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"alias":"stepup-loa-2","config":{"loa-condition-level":"2","loa-max-age":"36000"}}'
# QUIRK đã xác nhận: key PHẢI là "loa-condition-level"/"loa-max-age", KHÔNG phải
# "level"/"maxAge" như helpText gợi ý — sai key thì Keycloak âm thầm bỏ qua, LoA
# check sẽ không bao giờ true.

# 6. Bind flow "browser-stepup" làm browser flow CỦA RIÊNG client "web-portal-stepup"
#    (KHÔNG bind cho "web-portal" — đã có regression thật khi bind nhầm, xem
#    KET-QUA-KIEM-TRA.md mục "Phát hiện phụ mới" — mọi login thường bị bắt OTP)
WEBPORTAL_STEPUP_ID=$(curl -s "$KC_URL/admin/realms/$REALM/clients?clientId=web-portal-stepup" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")
curl -s -X PUT "$KC_URL/admin/realms/$REALM/clients/$WEBPORTAL_STEPUP_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"authenticationFlowBindingOverrides":{"browser":"'"$(curl -s "$KC_URL/admin/realms/$REALM/authentication/flows" -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c "import json,sys; print([f['id'] for f in json.load(sys.stdin) if f['alias']=='browser-stepup'][0])")"'"}}'
```

**Tạo user demo `stepup-demo` + OTP thật (không dùng secretData tự chế):**

```
1. Tạo user thường qua Admin API (username: stepup-demo, set password tạm).
2. Set requiredActions: ["CONFIGURE_TOTP"] cho user này.
3. Đăng nhập qua trình duyệt thật (hoặc tự động hoá bằng Selenium/Playwright nếu
   cần chạy trong CI) để Keycloak tự sinh secret CONFIGURE_TOTP và hiển thị QR —
   LẤY secret base32 hiển thị lúc đó.
   QUIRK ĐÃ XÁC NHẬN: Keycloak dùng RAW BYTES của chuỗi secret tự sinh làm khoá
   HMAC-SHA1 để tính TOTP — KHÔNG base32-decode secret trước như pyotp/PyJWT mặc
   định làm. Muốn tính mã OTP hợp lệ bằng script (không qua trình duyệt), phải tự
   viết hàm TOTP dùng raw bytes của secret string làm key, không dùng pyotp trực
   tiếp trên secret base32 đó.
4. Xác nhận: đăng nhập qua $KC_URL/realms/ztlab/protocol/openid-connect/auth
   với client_id=web-portal-stepup&acr_values=high phải yêu cầu OTP thật, và
   sau khi nhập đúng mã, token trả về phải có "acr":"high".
```

**Nghiệm thu bắt buộc sau khi làm xong (đừng bỏ qua — đã có tiền lệ regression thật):**
- Login bình thường qua client `web-portal` (KHÔNG có `acr_values`) → KHÔNG bị bắt OTP.
- Login qua `web-portal-stepup` với `acr_values=high` → bắt OTP thật, token có `acr:"high"`.
- Giao dịch >10tr với token `acr!=high` → OPA/app đều trả 401/403 (`step_up_required`).
- Giao dịch >10tr với token `acr:"high"` sau OTP → thành công (200).
- Chạy lại toàn bộ regression: `bash scripts/health-check.sh` (kỳ vọng FAIL=0),
  `python3 tests/test_service_graph_consistency.py` (2/2 PASS).

**Sau khi xác nhận đúng, nhớ thêm bước này vào một hàm idempotent trong
`scripts/deploy-app.sh`** (theo đúng mẫu hàm `deploy_audience_mapper()` đã có sẵn
trong file đó) để việc này tự động hoá hoàn toàn cho lần deploy sau nữa — không
phải chạy tay lại từ đầu mỗi lần.

---

## 2. ƯU TIÊN THẤP — Không còn liên quan sau destroy

~~Dọn 1 flow rác `test-copy-flow` trong Postgres của Keycloak (tạo ra lúc thử
nghiệm cách script hoá mục 1, làm hỏng API liệt-kê-flow của admin nhưng KHÔNG
ảnh hưởng login thật)~~ — **hết cần làm**, vì hạ tầng đã destroy, Postgres mới sẽ
sạch từ đầu. Không cần chạy 2 lệnh SQL DELETE đã đề xuất trước đó nữa.

---

## 3. [ĐÃ XONG 2026-09-08] Các gap nhỏ khác

1. **[XONG] `services/web-portal/main.py` — forward `X-Forwarded-For` (T-5.1):**
   đã thêm `X-Forwarded-For` vào 2 điểm gọi còn thiếu — `_lookup_account()` và
   `_create_bank_account_with_token()` (dùng chung ở luồng first-login/tạo tài
   khoản lúc đăng nhập lần đầu). Cả 4 hàm gọi `api-gateway` từ web-portal giờ
   đều forward IP client thật. `py_compile` xác nhận cú pháp hợp lệ.

2. **[XONG] Overhead ~100ms — đã đo tách bạch (T-5.3b):** đổi
   `services/api-gateway/main.py` và `services/payment-service/main.py` sang
   dùng 1 `httpx.AsyncClient` chung (khởi tạo ở `@app.on_event("startup")`,
   đóng ở `shutdown`) thay vì tạo mới mỗi request — áp dụng cho TẤT CẢ endpoint
   gọi cross-service ở cả 2 file (không chỉ `get_account`/`proxy_get_account`
   như nghi vấn gốc, kể cả `process_payment`/`proxy_create_account`/
   `proxy_list_accounts`/`proxy_list_transactions`). Build lại 2 image, import
   vào cả 3 node K3s AWS, rolling restart, xác nhận digest đúng image mới.
   `test_service_graph_consistency.py` PASS, `health-check.sh` PASS=30 WARN=6
   FAIL=0 (không đổi so với trước).

   **Phát hiện phụ trong lúc đo lại:** endpoint `GET /accounts/ACC-1001` ban đầu
   trả 503 `CERTIFICATE_VERIFY_FAILED` — KHÔNG liên quan gì đến thay đổi
   `httpx.AsyncClient` ở trên. Nguyên nhân thật: `spire-agent` DaemonSet bên
   OpenStack bị CrashLoopBackOff nhiều giờ trong phiên làm việc này (do máy
   host bị suspend/resume + race lúc reboot upstream, xem log của phiên) —
   đúng loại lỗi đã ghi ở §T-2.1 (`istio-proxy` không tự reconnect SDS sau khi
   `spire-agent` bị thay pod → cert mTLS stale/hết hạn). Fix: rolling-restart
   `core-banking`/`account-service`/`transaction-service` bên OpenStack để lấy
   cert mới — sau đó endpoint trả 200 bình thường. Không sửa code, chỉ là thao
   tác vận hành (nhắc lại: SAU BẤT KỲ lần restart `spire-agent` nào, phải rolling
   restart theo toàn bộ pod nghiệp vụ bị ảnh hưởng, như đã ghi ở §T-2.1).

   Kết quả đo (`kubectl exec` vào `web-portal`, gọi qua mesh thật, JWT thật
   (tự refresh giữa chừng qua `refresh_token` vì `accessTokenLifespan=300s`
   ngắn hơn tổng thời gian chạy), n=1000 + warmup 100, throttle ~54 req/phút để
   không đụng `RATE_LIMIT_PER_MINUTE=60` sống — không nâng rate-limit tạm thời
   như lần đo T-5.3 gốc vì đây là thay đổi live-config bị chặn theo policy an
   toàn của phiên làm việc). Chạy nền hẳn bên trong pod `web-portal` (không qua
   `kubectl exec` giữ kết nối suốt 20+ phút) vì 2 lần thử trước bị cắt giữa
   chừng — 1 lần do token hết hạn, 1 lần do tunnel SSH tới AWS tự rớt ở phút 21.

   | Cấu hình | p50 | p50 CI95% | p95 | p95 CI95% | p99 | p99 CI95% | mean |
   |---|---|---|---|---|---|---|---|
   | A — Gốc (per-request AsyncClient, đo 2026-09-05) | 108.65 | [108.08, 109.35] | 133.23 | [130.50, 137.24] | 166.59 | [153.60, 218.65] | 112.94 |
   | A' — Shared AsyncClient (đo 2026-09-08, phiên này) | 147.08 | [145.13, 148.91] | 249.43 | [244.48, 255.07] | 321.35 | [302.56, 334.36] | 168.66 |

   1000/1000 thành công (0 lỗi) ở A'.

   **Kết quả NGƯỢC với giả thuyết — A' CHẬM HƠN A, không nhanh hơn** (p50 tăng
   ~35%, p95 tăng ~87%, p99 tăng ~93%). Đây là số liệu thật, không phải suy
   đoán, nhưng **KHÔNG kết luận "shared client làm chậm hơn"** vì phép so sánh
   A vs A' lần này KHÔNG sạch (khác điều kiện đo, không chỉ khác đúng 1 biến
   `httpx.AsyncClient` như thiết kế gốc của T-5.3):
   - A đo ngày 2026-09-05 trên hạ tầng vừa deploy xong, chưa qua bất kỳ sự cố
     nào. A' đo ngày 2026-09-08 sau một phiên làm việc đầy sự cố nối tiếp nhau
     (máy bị suspend/resume, `spire-agent` crashloop nhiều giờ, cert mTLS phải
     làm mới, tunnel SSH tự rớt, RabbitMQ/nova phải restart) — hạ tầng CÓ THỂ
     đang ở trạng thái tải/hao mòn cao hơn hẳn lúc đo A, không liên quan gì
     đến code.
   - Không đo lại "A" (per-request client, code cũ) NGAY TRƯỚC A' trong cùng
     phiên này để có đối chứng cùng điều kiện hạ tầng — đây là thiếu sót
     phương pháp thật sự, cần sửa nếu muốn dùng số liệu này để kết luận.
   - Do đó: **giả thuyết gốc (per-request AsyncClient là thủ phạm chính của
     ~100ms overhead) vẫn CHƯA được xác nhận hay bác bỏ dứt điểm** — chỉ có
     thể nói chắc chắn: sau khi đổi sang shared client, hệ thống hôm nay đo
     được p50=147ms/mean=169ms, không thấy cải thiện rõ ràng như kỳ vọng.
   - Việc code (shared `httpx.AsyncClient`) vẫn giữ nguyên vì bản thân nó là
     cải tiến đúng đắn về mặt kỹ thuật (giảm số lần bắt tay mTLS, tránh rò rỉ
     connection pool) bất kể kết quả đo — không revert.
   - **Cần làm nếu muốn kết luận dứt điểm (chưa làm, ngoài phạm vi phiên này):**
     đo lại cả A và A' trong CÙNG một phiên hạ tầng ổn định (không có sự cố xen
     giữa), lý tưởng là revert tạm về per-request client, đo A ngay trước khi
     đổi lại sang A' để đo A', loại bỏ hoàn toàn biến "hạ tầng khác thời điểm".

3. **[XONG] `scripts/gen-rego-acl.py` / `scripts/gen-networkpolicy.py` giờ được
   gọi tự động:** thêm hàm `regenerate_policy_files()` vào `scripts/deploy-app.sh`,
   gọi đầu tiên trong `main()` (trước `apply_namespaces`) — chạy trước MỌI bước
   đụng tới file sinh ra, không chỉ trước configmap `opa-policies` (namespace
   policy/network đụng tới sớm hơn, ở `apply_network_policies`). Xác nhận:
   `bash -n` cú pháp hợp lệ, chạy 2 script cho ra `git diff` rỗng (đúng trạng
   thái hiện tại), `test_service_graph_consistency.py` PASS lại sau đó.

---

## 4. Đã ĐẠT, không cần làm lại — chỉ để đối chiếu khi deploy lại

Toàn bộ các mục sau đã sửa TRONG FILE (không phải chỉ sửa sống trên cluster cũ),
sẽ tự động đúng lại khi deploy mới, KHÔNG cần thao tác gì thêm:

- Bug nghiêm trọng `io.jwt.decode_verify()` (thiếu `"aud"` trong constraints) — đã
  sửa trong `opa/policies/zta_policy.rego`.
- Rate limit chuyển sang Redis (`services/api-gateway/main.py`).
- `_jwks_refresh_loop` retry 5s thay vì 300s (`services/api-gateway/main.py`).
- `source_ip`/XFF cho 3 endpoint chính (`services/web-portal/main.py`,
  `services/api-gateway/main.py`).
- OPA `replicas: 3` + PodDisruptionBudget cho CẢ 2 cluster (`opa/deployment.yaml`
  AWS, `k8s/financial/os-security.yaml` OpenStack).
- Client Keycloak `web-portal-stepup` (`k8s/keycloak/realm-config.json`) — CHỈ
  client, chưa gồm flow (xem mục 1).
- Mọi sửa đổi khác thuộc GĐ0–GĐ5 của `KE-HOACH-SUA-HE-THONG.md` (SPIRE bootstrap,
  NetworkPolicy theo ma trận, device_trust wiring, IDOR fix, fraud-chain fix,
  v.v.) — xem `KET-QUA-KIEM-TRA.md` để tra cứu chi tiết từng mục.

---

*File này chỉ có giá trị cho tới khi mục 1 được làm xong — sau đó nên xoá hoặc
gộp phần "đã đạt" vào `KET-QUA-KIEM-TRA.md` rồi xoá file này để tránh trùng lặp
tài liệu.*
