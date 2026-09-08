# ZTLab - api-gateway

import asyncio
import os
import time
import uuid

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Header, HTTPException, Request
from jose import JWTError, jwk, jwt
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import AUTH_FAILURES, SERVICE_UP

SERVICE = "api-gateway"
CLOUD = "aws"
PAYMENT_SERVICE_URL = os.getenv("PAYMENT_SERVICE_URL", "http://payment-service:8080").rstrip("/")
JWT_SECRET = os.getenv("JWT_DEV_SECRET", "")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "")

# Issuer và JWKS URL trước đây là 2 hằng số hardcode độc lập, phải tự tay giữ
# khớp với cấu hình THẬT của Keycloak (KC_HOSTNAME/KC_HOSTNAME_PORT). Lệch 1
# ký tự giữa chúng (đã xảy ra ngày 2026-08-13, thiếu KC_HOSTNAME_PORT khiến
# issuer thật lệch port) làm toàn bộ JWT bị từ chối, mất nhiều giờ để lần ra.
# Giờ lấy cả 2 giá trị từ chính OIDC discovery document Keycloak tự công bố —
# nguồn sự thật duy nhất, không cần đồng bộ tay.
JWT_ISSUER_OVERRIDE = os.getenv("JWT_ISSUER", "")  # để trống = luôn theo discovery; đặt tay chỉ dùng khi cần ghim khẩn cấp
JWKS_URL_OVERRIDE = os.getenv("JWKS_URL", "")
_KEYCLOAK_REALM_BASE = os.getenv(
    "KEYCLOAK_REALM_BASE", "http://keycloak.identity.svc.cluster.local:8080/realms/ztlab"
).rstrip("/")
OIDC_DISCOVERY_URL = f"{_KEYCLOAK_REALM_BASE}/.well-known/openid-configuration"

# Giá trị dự phòng nếu discovery chưa chạy được lần nào (VD Keycloak chưa kịp
# lên khi api-gateway khởi động) — không để service crash hoàn toàn, chỉ
# fail-closed như bình thường cho tới khi discovery thành công.
_jwt_issuer = JWT_ISSUER_OVERRIDE or "http://keycloak.ztlab.local:8180/realms/ztlab"
_jwks_uri = JWKS_URL_OVERRIDE or f"{_KEYCLOAK_REALM_BASE}/protocol/openid-connect/certs"
# T-4.2: ngưỡng theo QĐ 2345/QĐ-NHNN, TT 50/2024/TT-NHNN — cùng giá trị với
# STEP_UP_SINGLE_VND/STEP_UP_DAILY_VND trong opa/policies/zta_policy.rego.
STEP_UP_SINGLE_VND = 10_000_000
STEP_UP_DAILY_VND = 20_000_000
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
ALLOW_DEV_TOKENS = os.getenv("ALLOW_DEV_TOKENS", "false").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://redis.financial.svc.cluster.local:6379/0")
IP_BLOCK_ENABLED = os.getenv("IP_BLOCK_ENABLED", "true").lower() == "true"

app = FastAPI(title="ZTLab API Gateway")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)

_jwks_keys: list = []
_redis: aioredis.Redis | None = None
# T-5.3: 1 client dùng chung cho mọi hop tới payment-service, tạo lúc startup
# thay vì tạo mới mỗi request — tránh bắt tay mTLS mới cho mỗi lệnh gọi liên
# dịch vụ (nghi vấn nguyên nhân ~100ms overhead, xem KET-QUA-KIEM-TRA.md T-5.3
# và VIEC-CON-TON-DONG.md mục 3.2). Timeout vẫn truyền riêng từng lệnh gọi để
# giữ nguyên hành vi cũ (mỗi endpoint có ngưỡng timeout khác nhau).
_http_client: httpx.AsyncClient | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return _redis


async def _is_ip_blocked(ip: str) -> bool:
    if not IP_BLOCK_ENABLED:
        return False
    try:
        r = await _get_redis()
        return bool(await r.exists(f"ztlab:blocked_ip:{ip}"))
    except Exception:
        return False


def _load_oidc_config() -> None:
    """Nạp issuer + JWKS URI từ OIDC discovery document của Keycloak, thay vì
    2 hằng số hardcode độc lập. Nếu discovery lỗi, fallback dùng override/URL
    JWKS mặc định (đã tính sẵn) để không phá vỡ hoàn toàn service."""
    global _jwks_keys, _jwt_issuer, _jwks_uri
    issuer = _jwt_issuer
    jwks_uri = _jwks_uri
    try:
        disc = httpx.get(OIDC_DISCOVERY_URL, timeout=5)
        disc.raise_for_status()
        disc_data = disc.json()
        disc_issuer = disc_data.get("issuer")
        disc_jwks_uri = disc_data.get("jwks_uri")
        if not disc_issuer or not disc_jwks_uri:
            raise ValueError("discovery document missing issuer/jwks_uri")
        if not JWT_ISSUER_OVERRIDE:
            issuer = disc_issuer
        if not JWKS_URL_OVERRIDE:
            jwks_uri = disc_jwks_uri
    except Exception as exc:
        logger.warn("oidc_discovery_failed", error=str(exc), discovery_url=OIDC_DISCOVERY_URL,
                    fallback_issuer=issuer, fallback_jwks_uri=jwks_uri)

    try:
        resp = httpx.get(jwks_uri, timeout=5)
        resp.raise_for_status()
        _jwks_keys = [jwk.construct(k) for k in resp.json().get("keys", []) if k.get("use") == "sig"]
        _jwt_issuer = issuer
        _jwks_uri = jwks_uri
        logger.info("oidc_config_loaded", key_count=len(_jwks_keys), issuer=_jwt_issuer, jwks_uri=_jwks_uri)
    except Exception as exc:
        logger.warn("jwks_load_failed", error=str(exc), jwks_uri=jwks_uri)


class PaymentRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"
    channel: str = "api"
    country: str | None = None
    device_trust: str = "unknown"


# T-5.1: TCP-level peer address (request.client.host) không dùng được ở
# đây — istio-proxy sidecar terminate kết nối rồi forward vào app qua
# loopback, nên giá trị này LUÔN là 127.0.0.1/127.0.0.6 bất kể client thật
# là ai (xác nhận thật, KET-QUA-KIEM-TRA.md §T-0.3: quan sát trên toàn bộ
# traffic thật trong nhiều giờ, không có ngoại lệ). Istio KHÔNG tự thêm
# X-Forwarded-For cho traffic đông-tây (sidecar-to-sidecar) — không có
# `numTrustedProxies` tương đương cho sidecar trong Istio (chỉ Ingress
# Gateway có khái niệm này); phải tự relay ở tầng app. NGUỒN DUY NHẤT gọi
# vào các endpoint này là web-portal (service_acl, T-1.1, xác thực qua
# SPIFFE ở OPA trước khi tới đây) — nên coi "web-portal" là 1 trusted proxy
# duy nhất (tương đương numTrustedProxies=1): tin X-Forwarded-For nó gửi
# (web-portal/main.py::_client_ip lấy đúng client thật vì bản thân nó KHÔNG
# bị terminate — xem comment ở đó), lấy giá trị ĐẦU TIÊN nếu có danh sách.
def _source_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# T-5.2: dict trong tiến trình (_recent_by_source cũ) chỉ đúng khi có ĐÚNG 1
# replica — api-gateway chạy nhiều pod sau cùng 1 Service, LB round-robin giữa
# chúng, nên cùng 1 source_ip bị rải ra nhiều dict RIÊNG BIỆT không đồng bộ =>
# giới hạn thật sự cao gấp N lần cấu hình (N = số replica) mà không có cảnh
# báo gì. Chuyển sang Redis sorted set (member duy nhất nhờ uuid, score =
# timestamp) dùng chung giữa mọi replica: ZREMRANGEBYSCORE cắt các entry cũ
# hơn 60s, ZADD entry mới, ZCARD đếm — tương đương "sliding window" của deque
# cũ nhưng nhìn thấy toàn cụm.
async def _check_rate_limit(source_ip: str) -> None:
    now = time.time()
    key = f"ztlab:ratelimit:{source_ip}"
    r = await _get_redis()
    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, now - 60)
    pipe.zadd(key, {f"{now}:{uuid.uuid4()}": now})
    pipe.zcard(key)
    pipe.expire(key, 65)
    _, _, count, _ = await pipe.execute()
    if count > RATE_LIMIT_PER_MINUTE:
        logger.warn("rate_limit_exceeded", source_ip=source_ip, count=count)
        raise HTTPException(status_code=429, detail="rate limit exceeded")


def _require_role(claims: dict, role: str, source_ip: str) -> None:
    roles = claims.get("realm_access", {}).get("roles", [])
    if role not in roles:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="insufficient_role").inc()
        logger.warn("authz_denied", required_role=role, user=claims.get("preferred_username","?"), source_ip=source_ip)
        raise HTTPException(status_code=403, detail=f"role '{role}' required")


def _decode_jwt(token: str, key, algorithms: list[str]) -> dict:
    kwargs = {
        "algorithms": algorithms,
        "issuer": _jwt_issuer,
    }
    if JWT_AUDIENCE:
        kwargs["audience"] = JWT_AUDIENCE
    else:
        kwargs["options"] = {"verify_aud": False}
    claims = jwt.decode(token, key, **kwargs)
    # jose.jwt.decode() only checks "aud" when the claim is PRESENT — a token
    # with no "aud" claim at all sails through silently (confirmed: jose 3.3.0).
    # Enforce presence ourselves, otherwise JWT_AUDIENCE is a no-op for any
    # token minted without an audience mapper.
    if JWT_AUDIENCE and "aud" not in claims:
        raise JWTError('Token is missing the "aud" claim')
    return claims


def _verify_token(authorization: str | None, source_ip: str) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="missing_bearer").inc()
        logger.warn("jwt_verification_failed", reason="missing_bearer", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()

    # RS256 via Keycloak JWKS (primary path)
    if _jwks_keys:
        for key in _jwks_keys:
            try:
                claims = _decode_jwt(token, key, ["RS256"])
                return claims
            except JWTError:
                continue
        # JWKS keys are loaded — token is invalid, do NOT fall back to HS256
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="invalid_jwt").inc()
        logger.warn("jwt_verification_failed", reason="invalid_rs256", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="invalid token")

    if not ALLOW_DEV_TOKENS:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="jwks_unavailable").inc()
        logger.warn("jwt_verification_failed", reason="jwks_unavailable_fail_closed", source_ip=source_ip)
        raise HTTPException(status_code=503, detail="token verifier unavailable")

    if not JWT_SECRET:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="dev_secret_missing").inc()
        logger.warn("jwt_verification_failed", reason="dev_secret_missing", source_ip=source_ip)
        raise HTTPException(status_code=503, detail="dev token verifier unavailable")

    # HS256 dev token is opt-in only. Do not enable this in production.
    try:
        return _decode_jwt(token, JWT_SECRET, ["HS256"])
    except JWTError as exc:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="invalid_jwt").inc()
        logger.warn("jwt_verification_failed", reason="invalid_jwt", source_ip=source_ip, error=str(exc))
        raise HTTPException(status_code=401, detail="invalid token") from exc


# T-5.4 (phát hiện phụ khi đo fail-closed OPA): khi _jwks_keys rỗng do lần nạp
# đầu thất bại — thường gặp nhất là race lúc pod vừa khởi động, istio-proxy
# chưa kịp sẵn sàng route egress nên _load_oidc_config() gọi Keycloak bị
# "Connection refused" dù Keycloak hoàn toàn khoẻ mạnh — vòng lặp cũ vẫn ngủ
# nguyên 300s trước khi thử lại, nghĩa là 1 pod "xui" khởi động đúng lúc đó sẽ
# fail-closed MỌI request JWT thật suốt tới 5 phút dù lỗi tự khỏi trong vài
# giây. Giờ retry nhanh (5s) cho tới khi thành công, chỉ giãn ra 300s một khi
# đã có key (đúng ý đồ ban đầu: 300s là chu kỳ làm mới định kỳ, không phải
# chu kỳ retry-khi-lỗi).
async def _jwks_refresh_loop() -> None:
    while True:
        if not _jwks_keys:
            _load_oidc_config()
            await asyncio.sleep(5 if not _jwks_keys else 300)
        else:
            await asyncio.sleep(300)


@app.on_event("startup")
async def startup() -> None:
    global _http_client
    _http_client = httpx.AsyncClient()
    _load_oidc_config()
    asyncio.create_task(_jwks_refresh_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    if _http_client is not None:
        await _http_client.aclose()


# T-4.2: khoá Redis cho tổng giao dịch trong ngày của 1 tài khoản — OPA gọi
# GET /internal/daily-cumulative (qua http.send) để quyết định requires_step_up
# (luỹ kế >20 triệu/ngày, QĐ 2345/TT 50/2024/TT-NHNN) TRƯỚC KHI request tới
# được đây — nên số đọc được ở đây luôn là số liệu TRƯỚC giao dịch đang xét.
def _daily_cumulative_key(account: str) -> str:
    day = time.strftime("%Y-%m-%d", time.gmtime())
    return f"api-gateway:daily-cumulative:{account}:{day}"


async def _daily_cumulative_after(account: str, amount: float) -> float:
    """Luỹ kế NẾU giao dịch đang xét thành công — dùng để xét step-up TRƯỚC
    khi thật sự tăng bộ đếm (bộ đếm chỉ tăng sau khi payment-service xác nhận
    thành công, xem cuối create_payment)."""
    redis = await _get_redis()
    raw = await redis.get(_daily_cumulative_key(account))
    before = float(raw) if raw else 0.0
    return before + amount


@app.get("/internal/daily-cumulative")
async def internal_daily_cumulative(account: str):
    redis = await _get_redis()
    raw = await redis.get(_daily_cumulative_key(account))
    return {"account": account, "cumulative": float(raw) if raw else 0.0}


@app.post("/payments")
async def create_payment(request: Request, body: PaymentRequest, authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    if await _is_ip_blocked(source_ip):
        logger.warn("ip_blocked_request", source_ip=source_ip, path="/payments")
        raise HTTPException(status_code=403, detail={"reason": "ip_blocked", "source_ip": source_ip, "message": "IP bị chặn bởi hệ thống bảo mật"})
    await _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-write", source_ip)
    trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))

    # T-4.2: ngưỡng step-up theo QĐ 2345/QĐ-NHNN, TT 50/2024/TT-NHNN — cùng
    # logic đã viết ở opa/policies/zta_policy.rego (requires_step_up,
    # STEP_UP_SINGLE_VND/STEP_UP_DAILY_VND), nhưng OPA hiện KHÔNG xác minh
    # được BẤT KỲ chữ ký JWT thật nào từ Keycloak trên hạ tầng này (lỗi có
    # sẵn từ trước T-4.2, xác nhận qua opa eval độc lập + đối chứng PyJWT —
    # xem KET-QUA-KIEM-TRA.md §T-4.2) nên `jwt_payload.acr` không bao giờ
    # đọc được ở tầng OPA. Chặn tạm ở đây (đã verify JWT thật ở _verify_token
    # phía trên, "claims" tin cậy được) cho tới khi lỗi OPA được sửa.
    if body.amount > STEP_UP_SINGLE_VND or await _daily_cumulative_after(body.from_account, body.amount) > STEP_UP_DAILY_VND:
        if claims.get("acr") != "high":
            logger.warn("step_up_required", trace_id=trace_id, amount=body.amount, from_account=body.from_account, acr=claims.get("acr"))
            raise HTTPException(status_code=401, detail={
                "reason": "step_up_required",
                "message": "Giao dịch vượt ngưỡng, cần xác thực bổ sung (OTP)",
            })
    try:
        response = await _http_client.post(
            f"{PAYMENT_SERVICE_URL}/payments",
            json=body.model_dump(),
            headers={"X-Trace-ID": trace_id, "X-User-ID": str(claims.get("sub", "unknown")), "Authorization": authorization},
            timeout=15,
        )
    except Exception as exc:
        logger.error("payment_route_failed", trace_id=trace_id, error=str(exc))
        raise HTTPException(status_code=503, detail="payment service unavailable") from exc
    if response.status_code >= 400:
        try:
            body = response.json()
            detail = body.get("detail", body) if isinstance(body, dict) else body
        except Exception:
            detail = "upstream payment service error"
        raise HTTPException(status_code=response.status_code, detail=detail)
    try:
        redis = await _get_redis()
        key = _daily_cumulative_key(body.from_account)
        await redis.incrbyfloat(key, body.amount)
        await redis.expire(key, 2 * 24 * 3600)
    except Exception as exc:
        logger.error("daily_cumulative_update_failed", trace_id=trace_id, error=str(exc))
    return response.json()


@app.post("/accounts")
async def create_account(request: Request, authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    await _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-write", source_ip)
    body = await request.json()
    # Enforce: new account must belong to the authenticated user
    if body.get("owner") and body["owner"] != claims.get("preferred_username"):
        raise HTTPException(status_code=403, detail="cannot create account for another user")
    try:
        resp = await _http_client.post(f"{PAYMENT_SERVICE_URL}/accounts", json=body, timeout=10)
        if resp.status_code == 409:
            raise HTTPException(status_code=409, detail="account_id already exists")
        resp.raise_for_status()
        return resp.json()
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="account service unavailable") from exc


@app.get("/accounts")
async def list_accounts(request: Request, owner: str = "", authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    await _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-read", source_ip)
    roles = claims.get("realm_access", {}).get("roles", [])
    if "security-admin" in roles:
        params = {"owner": owner} if owner else {}
    else:
        params = {"owner": claims.get("preferred_username", "")}
    try:
        resp = await _http_client.get(f"{PAYMENT_SERVICE_URL}/accounts", params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail="account service error") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="account service unavailable") from exc


@app.get("/accounts/{account_id}")
async def get_account(account_id: str, request: Request, authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    await _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-read", source_ip)
    try:
        resp = await _http_client.get(f"{PAYMENT_SERVICE_URL}/accounts/{account_id}", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # IDOR check: account must belong to the authenticated user
        if data.get("owner") != claims.get("preferred_username"):
            AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="idor_attempt").inc()
            logger.warn("idor_attempt", account_id=account_id,
                        user=claims.get("preferred_username"), source_ip=source_ip)
            raise HTTPException(status_code=403, detail="access denied")
        return data
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail="account not found") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="account service unavailable") from exc


@app.get("/transactions")
async def get_transactions(request: Request, account_id: str = "", limit: int = 20,
                           authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    await _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-read", source_ip)
    roles = claims.get("realm_access", {}).get("roles", [])
    if "security-admin" not in roles:
        # IDOR fix (T-1.3): trước đây account_id được truyền thẳng xuống
        # payment-service không hề đối chiếu quyền sở hữu — bất kỳ user
        # financial-read nào cũng đọc được lịch sử giao dịch của account
        # bất kỳ, khác với /accounts/{account_id} vài dòng trên vốn đã
        # kiểm đúng. Giờ áp cùng kiểm tra: bắt buộc có account_id, và
        # account đó phải thuộc chính người gọi.
        if not account_id:
            raise HTTPException(status_code=400, detail="account_id is required")
        try:
            acc_resp = await _http_client.get(f"{PAYMENT_SERVICE_URL}/accounts/{account_id}", timeout=10)
            acc_resp.raise_for_status()
            account = acc_resp.json()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail="account not found") from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="account service unavailable") from exc
        if account.get("owner") != claims.get("preferred_username"):
            AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="idor_attempt").inc()
            logger.warn("idor_attempt", account_id=account_id, endpoint="/transactions",
                        user=claims.get("preferred_username"), source_ip=source_ip)
            raise HTTPException(status_code=403, detail="access denied")
    params: dict = {"limit": min(limit, 100)}
    if account_id:
        params["account_id"] = account_id
    try:
        resp = await _http_client.get(f"{PAYMENT_SERVICE_URL}/transactions", params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="transaction service unavailable") from exc


@app.get("/health")
async def health():
    return {
        "status": "ok", "service": SERVICE, "cloud": CLOUD,
        "jwks_keys_loaded": len(_jwks_keys),
        "active_issuer": _jwt_issuer,
        "active_jwks_uri": _jwks_uri,
    }
