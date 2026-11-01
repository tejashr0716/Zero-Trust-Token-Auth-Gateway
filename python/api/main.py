import os
import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from python.database.connection import init_db_pool, close_db_pool, get_db_pool
from python.services.cpp_bridge import SentinelTrustEngine
from python.services.redis_service import (
    init_redis, close_redis, revoke_token_in_redis, is_token_revoked_in_redis,
    record_auth_metric, update_ip_threat, get_ip_threat, publish_security_alert
)
from python.services.rabbitmq_service import init_rabbitmq, close_rabbitmq, publish_threat_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentineltrust.api")

engine: Optional[SentinelTrustEngine] = None

def get_engine() -> SentinelTrustEngine:
    global engine
    if engine is None:
        engine = SentinelTrustEngine()
    return engine

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Threat visualizer client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Threat visualizer client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing SentinelTrust Security Gateway Services...")
    await init_db_pool()
    await init_redis()
    await init_rabbitmq()
    eng = get_engine()

    # Pre-seed Bloom filter from DB
    try:
        db = await get_db_pool()
        async with db.acquire() as conn:
            revoked_rows = await conn.fetch("SELECT token_id FROM security_tokens WHERE revoked = TRUE;")
            for r in revoked_rows:
                eng.bloom_add(r["token_id"])
            logger.info(f"Loaded {len(revoked_rows)} revoked tokens into C++ Bloom filter.")
    except Exception as e:
        logger.warning(f"Could not preload revoked tokens: {e}")

    yield
    logger.info("Shutting down SentinelTrust Services...")
    await close_rabbitmq()
    await close_redis()
    await close_db_pool()

app = FastAPI(
    title="SentinelTrust Zero-Trust Token Auth Gateway & Threat Detection",
    version="1.0.0",
    description="Sub-Microsecond Zero-Trust Token Verification, Bloom Revocation, and Security Threat Analytics Engine",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Schemas
class TokenIssueRequest(BaseModel):
    client_id: str
    service_id: str
    claims: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = 86400

class TokenVerifyRequest(BaseModel):
    token_id: str
    client_id: str
    service_id: str
    signature: str
    issued_at_sec: int
    expires_at_sec: int
    requested_endpoint: str = "/api/v1/resource"
    client_ip: str = "10.240.10.15"

class TokenRevokeRequest(BaseModel):
    token_id: str
    reason: str = "COMPROMISED_CREDENTIALS"

web_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
if os.path.exists(web_dir):
    app.mount("/static", StaticFiles(directory=web_dir), name="static")

@app.get("/", include_in_schema=False)
@app.get("/demo", include_in_schema=False)
async def serve_dashboard():
    index_path = os.path.join(web_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>SentinelTrust Security Gateway Online</h1>")

@app.get("/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "SentinelTrust Zero-Trust Security Gateway",
        "crypto_core": "C++ SIMD Token & Bloom Filter Engine Loaded",
        "active_websockets": len(ws_manager.active_connections)
    }

@app.get("/api/v1/services")
async def list_services():
    db = await get_db_pool()
    async with db.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM services ORDER BY service_id ASC;")
        return [dict(r) for r in rows]

@app.post("/api/v1/tokens/issue", status_code=status.HTTP_201_CREATED)
async def issue_token(req: TokenIssueRequest):
    db = await get_db_pool()
    eng = get_engine()

    token_id = f"tok_{uuid.uuid4().hex[:12]}"
    now_sec = int(time.time())
    expires_sec = now_sec + req.ttl_seconds

    # Cryptographic signature computed via C++ engine algorithm
    signature = eng.compute_signature(token_id, req.client_id, req.service_id, secret_seed=42)

    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO security_tokens (token_id, client_id, service_id, claims_json, issued_at, expires_at, revoked)
            VALUES ($1, $2, $3, $4, TO_TIMESTAMP($5), TO_TIMESTAMP($6), FALSE);
            """,
            token_id, req.client_id, req.service_id, json.dumps(req.claims), now_sec, expires_sec
        )

    return {
        "token_id": token_id,
        "client_id": req.client_id,
        "service_id": req.service_id,
        "issued_at_sec": now_sec,
        "expires_at_sec": expires_sec,
        "signature": signature,
        "claims": req.claims
    }

@app.post("/api/v1/tokens/verify")
async def verify_token(req: TokenVerifyRequest):
    eng = get_engine()
    now_sec = int(time.time())

    # Get IP threat score from Redis
    ip_threat = await get_ip_threat(req.client_ip)
    ip_trust_score = max(0, int(100 - ip_threat))

    # Fast in-memory C++ evaluation (Bloom filter + Expiry + Signature + Anomaly)
    auth_result = eng.verify_token(
        token_id=req.token_id,
        client_id=req.client_id,
        service_id=req.service_id,
        issued_at_sec=req.issued_at_sec,
        expires_at_sec=req.expires_at_sec,
        signature=req.signature,
        client_ip=req.client_ip,
        current_time_sec=now_sec,
        secret_seed=42,
        ip_trust_score=ip_trust_score
    )

    decision = auth_result["decision"]
    latency_us = round(auth_result["latency_ns"] / 1000.0, 3)

    # Record metric in Redis
    await record_auth_metric(decision)

    # If threat / denied, update IP threat and broadcast
    if decision != "ALLOWED":
        new_threat = await update_ip_threat(req.client_ip, delta_threat=15.0)
        threat_event = {
            "type": "SECURITY_ALERT",
            "threat_type": decision,
            "token_id": req.token_id,
            "client_id": req.client_id,
            "service_id": req.service_id,
            "source_ip": req.client_ip,
            "threat_score": auth_result["threat_score"],
            "reason": auth_result["reason"],
            "timestamp": time.time()
        }
        await publish_threat_event(f"threat.quarantine.{decision.lower()}", threat_event)
        await publish_security_alert(threat_event)
        asyncio.create_task(ws_manager.broadcast(threat_event))

    # Record audit log in PostgreSQL
    db = await get_db_pool()
    async with db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO access_audit_logs (token_id, client_id, service_id, requested_endpoint, decision, latency_us, source_ip)
            VALUES ($1, $2, $3, $4, $5, $6, $7);
            """,
            req.token_id, req.client_id, req.service_id, req.requested_endpoint, decision, latency_us, req.client_ip
        )

    return {
        "token_id": req.token_id,
        "decision": decision,
        "is_authorized": decision == "ALLOWED",
        "threat_score": auth_result["threat_score"],
        "latency_us": latency_us,
        "reason": auth_result["reason"]
    }

@app.post("/api/v1/tokens/revoke")
async def revoke_token(req: TokenRevokeRequest):
    eng = get_engine()

    # 1. Add to C++ In-Memory Bloom Filter for nanosecond instant rejection
    eng.bloom_add(req.token_id)

    # 2. Add to Redis Set
    await revoke_token_in_redis(req.token_id, req.reason)

    # 3. Update PostgreSQL
    db = await get_db_pool()
    async with db.acquire() as conn:
        res = await conn.execute(
            """
            UPDATE security_tokens
            SET revoked = TRUE, revoked_at = NOW()
            WHERE token_id = $1;
            """,
            req.token_id
        )

    alert = {
        "type": "TOKEN_REVOKED",
        "token_id": req.token_id,
        "reason": req.reason,
        "revoked_at": time.time()
    }
    await publish_security_alert(alert)
    asyncio.create_task(ws_manager.broadcast(alert))

    return {
        "status": "REVOKED",
        "token_id": req.token_id,
        "in_bloom_filter": True,
        "reason": req.reason
    }

@app.get("/api/v1/threats")
async def get_threats():
    db = await get_db_pool()
    async with db.acquire() as conn:
        incidents = await conn.fetch("SELECT * FROM threat_incidents ORDER BY incident_id DESC LIMIT 20;")
        audits = await conn.fetch("SELECT * FROM access_audit_logs ORDER BY log_id DESC LIMIT 20;")

        return {
            "incidents": [
                {
                    "incident_id": i["incident_id"],
                    "threat_type": i["threat_type"],
                    "severity": i["severity"],
                    "source_ip": i["source_ip"],
                    "client_id": i["client_id"],
                    "threat_score": i["threat_score"],
                    "action_taken": i["action_taken"],
                    "detected_at": i["detected_at"].isoformat()
                }
                for i in incidents
            ],
            "recent_audits": [
                {
                    "log_id": a["log_id"],
                    "token_id": a["token_id"],
                    "client_id": a["client_id"],
                    "service_id": a["service_id"],
                    "decision": a["decision"],
                    "latency_us": a["latency_us"],
                    "source_ip": a["source_ip"],
                    "created_at": a["created_at"].isoformat()
                }
                for a in audits
            ]
        }

@app.websocket("/ws/threats")
async def websocket_threats(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "CONNECTED",
            "message": "SentinelTrust Live Threat Stream Connected"
        })
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "PONG"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
