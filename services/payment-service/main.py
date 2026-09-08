# ZTLab - payment-service

import os
import time
import uuid
import httpx
from fastapi import FastAPI, Request, HTTPException
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import CROSS_CLOUD_LATENCY, TXN_TOTAL, SERVICE_UP
from shared.posture import DEVICE_POSTURE, DEVICE_POSTURE_REASONS

SERVICE = "payment-service"
CLOUD = "aws"
FRAUD_URL = os.getenv("FRAUD_SERVICE_URL", "http://fraud-detection:8080").rstrip("/")
CORE_BANKING_URL = os.getenv("CORE_BANKING_URL", "http://core-banking:8080").rstrip("/")
NOTIFICATION_URL = os.getenv("NOTIFICATION_SERVICE_URL", "http://127.0.0.1:15001").rstrip("/")
MAX_SINGLE_TXN = int(os.getenv("MAX_SINGLE_TXN_VND", str(500_000_000)))

app = FastAPI(title="ZTLab Payment Service")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)
logger.info("device_posture_self_check", posture=DEVICE_POSTURE, reasons=DEVICE_POSTURE_REASONS)

# T-5.3: 1 client dùng chung cho mọi hop ra fraud-detection/core-banking/
# notification-service, tạo lúc startup thay vì tạo mới mỗi request — tránh
# bắt tay mTLS mới cho mỗi lệnh gọi liên dịch vụ, kể cả cross-cloud
# (core-banking nằm bên OpenStack). Xem KET-QUA-KIEM-TRA.md T-5.3 và
# VIEC-CON-TON-DONG.md mục 3.2. Timeout vẫn truyền riêng từng lệnh gọi.
_http_client: httpx.AsyncClient | None = None


@app.on_event("startup")
async def startup() -> None:
    global _http_client
    _http_client = httpx.AsyncClient()


@app.on_event("shutdown")
async def shutdown() -> None:
    if _http_client is not None:
        await _http_client.aclose()


class PaymentRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = Field(default="VND")
    channel: str = Field(default="api")
    country: str | None = None
    device_trust: str = Field(default="unknown")

# T-1.5: payment-service used to compute the fraud-gate signature itself with
# a shared HMAC secret, even though fraud-detection is the one that actually
# computes the score -- a compromised payment-service could self-sign any
# score. fraud-detection now signs its own verdict with its SPIRE X.509-SVID
# private key (asymmetric, see shared/svid_sign.py); payment-service is a
# pure relay of that signature/cert from here on, nothing left to sign here.


@app.post("/payments")
async def process_payment(req: Request, body: PaymentRequest):
    trace_id = req.headers.get("X-Trace-ID", str(uuid.uuid4()))
    downstream_headers = {"X-Trace-ID": trace_id}
    authorization = req.headers.get("Authorization")
    if authorization:
        downstream_headers["Authorization"] = authorization
    if body.amount > MAX_SINGLE_TXN:
        TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="payment", status="rejected_amount_limit").inc()
        logger.warn("payment_rejected_amount_limit", trace_id=trace_id, amount=body.amount)
        raise HTTPException(status_code=400, detail="amount exceeds MAX_SINGLE_TXN_VND")

    payload = body.model_dump()
    try:
        fraud_response = await _http_client.post(f"{FRAUD_URL}/score", json=payload, headers=downstream_headers, timeout=10)
        fraud_response.raise_for_status()
    except Exception as exc:
        TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="payment", status="fraud_unavailable").inc()
        logger.error("fraud_service_unavailable", trace_id=trace_id, error=str(exc))
        raise HTTPException(status_code=503, detail="fraud service unavailable") from exc

    fraud = fraud_response.json()
    score = int(fraud.get("score", 100))
    gate = str(fraud.get("gate", "blocked"))
    if gate != "passed":
        TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="payment", status="blocked_fraud").inc()
        logger.audit("payment_blocked_fraud", trace_id=trace_id, fraud_score=score, fraud=fraud)
        raise HTTPException(status_code=403, detail={"reason": "fraud gate blocked", "fraud": fraud})

    start = time.time()
    try:
        core_response = await _http_client.post(
            f"{CORE_BANKING_URL}/transactions/execute",
            json={**payload, "trace_id": trace_id},
            headers={
                **downstream_headers,
                "X-Fraud-Gate": "passed",
                "X-Fraud-Score": str(score),
                "X-Fraud-Timestamp": str(fraud["timestamp"]),
                "X-Fraud-Signature": fraud["signature"],
                "X-Fraud-Cert": fraud["cert"],
                "X-Device-Posture": DEVICE_POSTURE,
                # T-4.1: trước đây device_trust chỉ cộng điểm rủi ro bên
                # trong fraud-detection, không bao giờ tới PDP (OPA)
                # — không thể chặn/step-up dựa trên nó. Giờ relay ra
                # header, cùng pattern với X-Device-Posture.
                "X-Device-Trust": body.device_trust,
            },
            timeout=10,
        )
        latency = time.time() - start
        CROSS_CLOUD_LATENCY.labels(source=SERVICE, target="core-banking", status=str(core_response.status_code)).observe(latency)
        core_response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="payment", status="core_denied").inc()
        logger.warn("core_banking_denied", trace_id=trace_id, fraud_score=score, status_code=exc.response.status_code)
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
    except Exception as exc:
        TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="payment", status="core_unavailable").inc()
        logger.error("core_banking_unavailable", trace_id=trace_id, error=str(exc))
        raise HTTPException(status_code=503, detail="core banking unavailable") from exc

    result = core_response.json()
    TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="payment", status="completed").inc()
    logger.audit("payment_completed", trace_id=trace_id, fraud_score=score, transaction_id=result.get("transaction_id"))

    # Extract sender info from JWT for email notification
    sender_name = None
    sender_email = None
    raw_auth = authorization or ""
    if raw_auth.startswith("Bearer "):
        try:
            import base64, json as _json
            parts = raw_auth[7:].split(".")
            if len(parts) >= 2:
                pad = parts[1] + "=" * (-len(parts[1]) % 4)
                claims = _json.loads(base64.urlsafe_b64decode(pad))
                sender_name  = claims.get("name") or claims.get("preferred_username")
                sender_email = claims.get("email")
        except Exception:
            pass

    try:
        notify_payload = {
            "trace_id":       trace_id,
            "event":          "payment_completed",
            "recipient":      body.from_account,
            "recipient_email": sender_email,
            "sender_name":    sender_name,
            "transaction": {
                **result,
                "from_account": body.from_account,
                "to_account":   body.to_account,
                "amount":       body.amount,
                "currency":     body.currency,
            },
        }
        await _http_client.post(f"{NOTIFICATION_URL}/notify", json=notify_payload, headers=downstream_headers, timeout=10)
    except Exception as exc:
        logger.warn("notification_send_failed", trace_id=trace_id, error=str(exc))
    return {"status": "completed", "trace_id": trace_id, "fraud": fraud, "core_banking": result}


@app.post("/accounts")
async def proxy_create_account(request: Request):
    body = await request.json()
    try:
        resp = await _http_client.post(f"{CORE_BANKING_URL}/accounts", json=body, timeout=5)
        if resp.status_code == 409:
            raise HTTPException(status_code=409, detail="account_id already exists")
        resp.raise_for_status()
        return resp.json()
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="core banking unavailable") from exc


@app.get("/accounts")
async def proxy_list_accounts(owner: str = ""):
    params = {"owner": owner} if owner else {}
    try:
        resp = await _http_client.get(f"{CORE_BANKING_URL}/accounts", params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="core banking unavailable") from exc


@app.get("/accounts/{account_id}")
async def proxy_get_account(account_id: str):
    try:
        resp = await _http_client.get(f"{CORE_BANKING_URL}/accounts/{account_id}", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="core banking unavailable") from exc


@app.get("/transactions")
async def proxy_list_transactions(account_id: str = "", limit: int = 20):
    params: dict = {"limit": min(limit, 100)}
    if account_id:
        params["account_id"] = account_id
    try:
        resp = await _http_client.get(f"{CORE_BANKING_URL}/transactions", params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="core banking unavailable") from exc


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD, "ts": time.time()}
