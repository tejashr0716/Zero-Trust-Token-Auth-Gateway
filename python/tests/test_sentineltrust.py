import time
import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from python.api.main import app, get_engine
from python.services.cpp_bridge import SentinelTrustEngine
from python.database.connection import close_db_pool
from python.services.redis_service import init_redis, close_redis, revoke_token_in_redis, is_token_revoked_in_redis, update_ip_threat, get_ip_threat
from python.services.rabbitmq_service import close_rabbitmq

@pytest.fixture(scope="module")
def cpp_engine():
    return SentinelTrustEngine()

@pytest_asyncio.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    await close_rabbitmq()
    await close_redis()
    await close_db_pool()

def test_cpp_engine_valid_token_verification(cpp_engine):
    token_id = "tok_test_valid_001"
    client_id = "client_worker"
    service_id = "svc_payment_core"
    sig = cpp_engine.compute_signature(token_id, client_id, service_id, secret_seed=42)

    res = cpp_engine.verify_token(
        token_id=token_id,
        client_id=client_id,
        service_id=service_id,
        issued_at_sec=1700000000,
        expires_at_sec=1700100000,
        signature=sig,
        client_ip="10.240.10.20",
        current_time_sec=1700050000,
        secret_seed=42,
        ip_trust_score=95
    )
    assert res["decision"] == "ALLOWED"
    assert res["threat_score"] == 0.0
    assert "verified" in res["reason"].lower()

def test_cpp_engine_tampered_signature(cpp_engine):
    token_id = "tok_test_tampered"
    res = cpp_engine.verify_token(
        token_id=token_id,
        client_id="client_worker",
        service_id="svc_payment_core",
        issued_at_sec=1700000000,
        expires_at_sec=1700100000,
        signature="sig_forged_invalid_hex",
        client_ip="10.240.10.20",
        current_time_sec=1700050000,
        secret_seed=42,
        ip_trust_score=95
    )
    assert res["decision"] == "DENIED_TAMPERED"
    assert res["threat_score"] >= 90.0

def test_cpp_engine_expired_token(cpp_engine):
    token_id = "tok_test_expired"
    sig = cpp_engine.compute_signature(token_id, "client_worker", "svc_payment_core", secret_seed=42)
    res = cpp_engine.verify_token(
        token_id=token_id,
        client_id="client_worker",
        service_id="svc_payment_core",
        issued_at_sec=1700000000,
        expires_at_sec=1700010000,
        signature=sig,
        client_ip="10.240.10.20",
        current_time_sec=1700050000,
        secret_seed=42,
        ip_trust_score=95
    )
    assert res["decision"] == "DENIED_EXPIRED"

def test_cpp_engine_bloom_revocation_lifecycle(cpp_engine):
    rev_token = f"tok_rev_{uuid.uuid4().hex[:8]}"
    sig = cpp_engine.compute_signature(rev_token, "client_worker", "svc_payment_core", secret_seed=42)

    # Before insertion
    assert cpp_engine.bloom_contains(rev_token) is False

    # Insert into Bloom filter
    cpp_engine.bloom_add(rev_token)
    assert cpp_engine.bloom_contains(rev_token) is True

    # Verification must be instantly denied
    res = cpp_engine.verify_token(
        token_id=rev_token,
        client_id="client_worker",
        service_id="svc_payment_core",
        issued_at_sec=1700000000,
        expires_at_sec=1700100000,
        signature=sig,
        client_ip="10.240.10.20",
        current_time_sec=1700050000,
        secret_seed=42,
        ip_trust_score=95
    )
    assert res["decision"] == "DENIED_REVOKED"
    assert res["threat_score"] >= 90.0

def test_cpp_engine_batch_verification(cpp_engine):
    tokens = []
    for i in range(15):
        tid = f"tok_batch_{i}"
        sig = cpp_engine.compute_signature(tid, "client_batch", "svc_order_engine", secret_seed=42)
        tokens.append({
            "token_id": tid,
            "client_id": "client_batch",
            "service_id": "svc_order_engine",
            "issued_at_sec": 1700000000,
            "expires_at_sec": 1700100000,
            "signature": sig
        })

    ctx = {
        "client_ip": "10.240.12.5",
        "current_time_sec": 1700050000,
        "secret_seed": 42,
        "ip_trust_score": 90
    }
    results = cpp_engine.batch_verify(tokens, ctx)
    assert len(results) == 15
    for r in results:
        assert r["decision"] == "ALLOWED"

@pytest.mark.asyncio
async def test_redis_revocation_and_threat_scoring():
    await init_redis()
    tok_id = f"tok_redis_{uuid.uuid4().hex[:6]}"
    assert await is_token_revoked_in_redis(tok_id) is False

    await revoke_token_in_redis(tok_id, "TEST_BREACH")
    assert await is_token_revoked_in_redis(tok_id) is True

    test_ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    t1 = await update_ip_threat(test_ip, 25.5)
    assert t1 == 25.5
    t2 = await get_ip_threat(test_ip)
    assert t2 == 25.5
    await close_redis()

@pytest.mark.asyncio
async def test_api_health(async_client):
    resp = await async_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "HEALTHY"
    assert "SentinelTrust" in data["service"]

@pytest.mark.asyncio
async def test_api_list_services(async_client):
    resp = await async_client.get("/api/v1/services")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 4
    service_ids = [s["service_id"] for s in data]
    assert "svc_payment_core" in service_ids
    assert "svc_order_engine" in service_ids

@pytest.mark.asyncio
async def test_api_token_lifecycle_issue_verify_revoke(async_client):
    # 1. Issue Token
    issue_payload = {
        "client_id": "client_qa_tester",
        "service_id": "svc_payment_core",
        "claims": {"role": "tester", "access": "write"},
        "ttl_seconds": 3600
    }
    issue_resp = await async_client.post("/api/v1/tokens/issue", json=issue_payload)
    assert issue_resp.status_code == 201
    tok_data = issue_resp.json()
    assert "token_id" in tok_data
    assert "signature" in tok_data

    # 2. Verify Valid Token
    verify_payload = {
        "token_id": tok_data["token_id"],
        "client_id": tok_data["client_id"],
        "service_id": tok_data["service_id"],
        "signature": tok_data["signature"],
        "issued_at_sec": tok_data["issued_at_sec"],
        "expires_at_sec": tok_data["expires_at_sec"],
        "requested_endpoint": "/api/v1/process_payment",
        "client_ip": "10.240.10.99"
    }
    verify_resp = await async_client.post("/api/v1/tokens/verify", json=verify_payload)
    assert verify_resp.status_code == 200
    verify_result = verify_resp.json()
    assert verify_result["decision"] == "ALLOWED"
    assert verify_result["is_authorized"] is True

    # 3. Revoke Token
    revoke_payload = {
        "token_id": tok_data["token_id"],
        "reason": "SECURITY_AUDIT_EXPIRED"
    }
    revoke_resp = await async_client.post("/api/v1/tokens/revoke", json=revoke_payload)
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "REVOKED"

    # 4. Verify Revoked Token (Must be Denied via Bloom filter)
    revoked_verify_resp = await async_client.post("/api/v1/tokens/verify", json=verify_payload)
    assert revoked_verify_resp.status_code == 200
    revoked_result = revoked_verify_resp.json()
    assert revoked_result["decision"] == "DENIED_REVOKED"
    assert revoked_result["is_authorized"] is False

@pytest.mark.asyncio
async def test_api_tampered_token_denial(async_client):
    tampered_payload = {
        "token_id": f"tok_{uuid.uuid4().hex[:8]}",
        "client_id": "attacker_bot",
        "service_id": "svc_auth_broker",
        "signature": "sig_bad_fake_signature",
        "issued_at_sec": int(time.time()),
        "expires_at_sec": int(time.time()) + 3600,
        "requested_endpoint": "/api/v1/admin/secrets",
        "client_ip": "198.51.100.99"
    }
    resp = await async_client.post("/api/v1/tokens/verify", json=tampered_payload)
    assert resp.status_code == 200
    res = resp.json()
    assert res["decision"] == "DENIED_TAMPERED"
    assert res["is_authorized"] is False
    assert res["threat_score"] > 80.0

@pytest.mark.asyncio
async def test_api_threats_list(async_client):
    resp = await async_client.get("/api/v1/threats")
    assert resp.status_code == 200
    data = resp.json()
    assert "incidents" in data
    assert "recent_audits" in data
    assert len(data["incidents"]) > 0

def test_spark_threat_detector_import():
    from python.spark.spark_threat_detector import run_federated_threat_analysis, build_spark_session
    assert callable(run_federated_threat_analysis)
    assert callable(build_spark_session)
