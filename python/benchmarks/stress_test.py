import asyncio
import random
import time
import statistics
import uuid
from httpx import AsyncClient, ASGITransport
from python.api.main import app, get_engine
from python.database.connection import close_db_pool
from python.services.redis_service import close_redis
from python.services.rabbitmq_service import close_rabbitmq

TOTAL_REQUESTS = 1200
CONCURRENCY = 15
SERVICES = ["svc_payment_core", "svc_order_engine", "svc_telemetry_hub", "svc_auth_broker"]

async def worker(client: AsyncClient, queue: asyncio.Queue, latencies: list):
    while True:
        try:
            payload = queue.get_nowait()
        except asyncio.QueueEmpty:
            break

        t0 = time.perf_counter()
        resp = await client.post("/api/v1/tokens/verify", json=payload)
        t1 = time.perf_counter()
        if resp.status_code == 200:
            latencies.append((t1 - t0) * 1000.0)

async def run_stress_test():
    print("=================================================================")
    print("  SentinelTrust Zero-Trust Token Verification Stress Test       ")
    print(f"  Target: {TOTAL_REQUESTS} tokens | Concurrency: {CONCURRENCY} workers")
    print("=================================================================\n")

    eng = get_engine()
    queue = asyncio.Queue()
    now_sec = int(time.time())

    for i in range(TOTAL_REQUESTS):
        tid = f"tok_stress_{i}_{uuid.uuid4().hex[:6]}"
        cid = f"client_worker_{i % 20}"
        sid = random.choice(SERVICES)

        # 85% valid, 15% tampered / attacks
        is_attack = (random.random() < 0.15)
        if is_attack:
            sig = "sig_forged_attack_hex"
            ip = f"198.51.100.{random.randint(1, 254)}"
        else:
            sig = eng.compute_signature(tid, cid, sid, secret_seed=42)
            ip = f"10.240.10.{random.randint(2, 250)}"

        queue.put_nowait({
            "token_id": tid,
            "client_id": cid,
            "service_id": sid,
            "signature": sig,
            "issued_at_sec": now_sec - 100,
            "expires_at_sec": now_sec + 86400,
            "requested_endpoint": f"/api/v1/{sid}/invoke",
            "client_ip": ip
        })

    latencies = []
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        start_time = time.perf_counter()
        tasks = [asyncio.create_task(worker(client, queue, latencies)) for _ in range(CONCURRENCY)]
        await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time

    await close_rabbitmq()
    await close_redis()
    await close_db_pool()

    latencies.sort()
    throughput = len(latencies) / total_time
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    print(f">> Completed:            {len(latencies)} / {TOTAL_REQUESTS} tokens verified")
    print(f">> Total Wall Time:      {total_time:.2f} seconds")
    print(f">> Sustained Throughput: {throughput:,.1f} verifications/sec")
    print(f">> Latency p50:          {p50:.2f} ms")
    print(f">> Latency p95:          {p95:.2f} ms")
    print(f">> Latency p99:          {p99:.2f} ms")
    print("=================================================================")

if __name__ == "__main__":
    asyncio.run(run_stress_test())
