import json
import os
import redis.asyncio as redis
from typing import Optional, Dict, Any, List

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "8"))

redis_client: Optional[redis.Redis] = None

async def init_redis() -> redis.Redis:
    global redis_client
    if redis_client is not None:
        try:
            await redis_client.aclose()
        except Exception:
            pass
        redis_client = None

    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        decode_responses=True
    )
    return redis_client

async def get_redis() -> redis.Redis:
    global redis_client
    if redis_client is None:
        await init_redis()
    return redis_client

async def close_redis():
    global redis_client
    if redis_client is not None:
        try:
            await redis_client.aclose()
        except Exception:
            pass
        redis_client = None

async def revoke_token_in_redis(token_id: str, reason: str = "MANUAL_REVOCATION"):
    client = await get_redis()
    await client.sadd("sentineltrust:revocations", token_id)
    await client.set(f"sentineltrust:revoked_info:{token_id}", reason, ex=86400 * 7)

async def is_token_revoked_in_redis(token_id: str) -> bool:
    client = await get_redis()
    return bool(await client.sismember("sentineltrust:revocations", token_id))

async def record_auth_metric(decision: str):
    client = await get_redis()
    key = f"sentineltrust:stats:{decision.lower()}"
    await client.incr(key)

async def update_ip_threat(ip: str, delta_threat: float, ttl: int = 3600) -> float:
    client = await get_redis()
    key = f"sentineltrust:ip_threat:{ip}"
    val = await client.incrbyfloat(key, delta_threat)
    await client.expire(key, ttl)
    return float(val)

async def get_ip_threat(ip: str) -> float:
    client = await get_redis()
    key = f"sentineltrust:ip_threat:{ip}"
    val = await client.get(key)
    return float(val) if val else 0.0

async def publish_security_alert(alert: Dict[str, Any]):
    client = await get_redis()
    await client.publish("sentineltrust:threat_alerts", json.dumps(alert))
