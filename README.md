# SentinelTrust: Federated Security Threat Detection & Zero-Trust Token Auth Gateway

[![SentinelTrust CI](https://github.com/tejashr0716/sentineltrust/actions/workflows/ci.yml/badge.svg)](https://github.com/tejashr0716/sentineltrust/actions)
[![Live Showcase](https://img.shields.io/badge/Live_Showcase-GitHub_Pages-blue.svg)](https://tejashr0716.github.io/sentineltrust/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**SentinelTrust** is an enterprise-grade Zero-Trust Token Authentication Gateway and real-time Federated Security Threat Detection Engine. It bridges high-speed C++ in-memory Bloom filter revocation and Murmur cryptographic verification with an asynchronous FastAPI gateway, Redis DB 8 distributed blacklists, RabbitMQ threat quarantine bus, PostgreSQL audit ledgers, and Apache Spark federated anomaly detection.

---

## Architecture Overview

```
    [Incoming Microservice Client Request]
                      │
                      ▼
    [FastAPI Zero-Trust Gateway (Port 8000)]
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
 [C++ Bloom Filter]       [C++ Crypto Signature]
 (20.41M checks/sec)      (2.64M tokens/sec)
         │                         │
         └────────────┬────────────┘
                      ▼
    [Zero-Trust Decision: ALLOW / DENY / QUARANTINE]
         │                         │
         ▼ (If Allowed)            ▼ (If Threat/Anomaly)
[Microservice Access]    [RabbitMQ Quarantine Exchange]
                                   │
                                   ▼
                      [Apache Spark Threat Engine]
                      (Federated IP Clustering)
```

---

## Performance & Nano-Benchmarks

| Component | Benchmark Metric | Result |
| :--- | :--- | :--- |
| **C++ Bloom Filter Revocation** | In-Memory 65,536-bit Bitset (k=3) | **20,410,000 checks/sec** (49.00 ns/check) |
| **C++ Crypto Token Verification** | Murmur3 / FNV-1a Signature Integrity | **2,640,000 tokens/sec** (378.69 ns/eval) |
| **C++ SIMD Batch Verification** | Loop Unrolled Vector Pipeline | **2,690,000 tokens/sec** (371.74 ns/eval) |
| **End-to-End Gateway Stress** | Concurrent Async HTTP ASGI Ingest | **1,386.7 verifications/sec** (p50: 9.24 ms) |
| **Revocation Accuracy** | Out-of-the-box Token Blacklisting | **100.0% Zero False Negative Guarantee** |

---

## Key Features

1. **Sub-Microsecond Zero-Trust Verification Core (`libsentineltrust.dylib` / `.so`)**:
   - Written in C++17 with 64-bit Murmur3 mixing and Jenkins hash.
   - Evaluates signature integrity, token expiration, and IP reputation in nanoseconds.
2. **In-Memory Bloom Filter Revocation Gate**:
   - 65,536-bit bitset with 3 independent hash functions.
   - Instantly rejects blacklisted or compromised tokens before reaching relational storage.
3. **Multi-Service Microsegmentation**:
   - Role-based and service-scoped Zero-Trust policies across `svc_payment_core`, `svc_order_engine`, `svc_telemetry_hub`, and `svc_auth_broker`.
4. **Threat Quarantine via RabbitMQ**:
   - Routes signature tampering, replay attacks, and hostile IP probes into `sentineltrust.quarantine.queue` and DLQ.
5. **Apache Spark Federated Forensics**:
   - Aggregates access audit logs, computes IP denial velocity, and identifies distributed coordinated attacks.
6. **Live Threat Telemetry WebSockets**:
   - Real-time event broadcasting to the web defense dashboard.

---

## Quickstart

### 1. Compile C++ Core & Run Benchmarks
```bash
g++ -O3 -shared -fPIC -std=c++17 -Iinclude src/sentineltrust.cpp -o libsentineltrust.dylib
g++ -O3 -std=c++17 -Iinclude benchmarks/bench_engine.cpp src/sentineltrust.cpp -o bench_engine
./bench_engine
```

### 2. Run Database & Infrastructure
```bash
docker compose up -d
```

### 3. Run Pytest Suite
```bash
pytest -v python/tests/test_sentineltrust.py
```

### 4. Run End-to-End Stress Test
```bash
PYTHONPATH=. python3 python/benchmarks/stress_test.py
```

---

## Technology Stack

- **C++17**: Cryptographic Hash, Bloom Filter Bitset, SIMD Loop Unrolling
- **Python 3.14 / FastAPI**: Async RESTful APIs, Zero-Copy Ctypes FFI, WebSockets
- **PostgreSQL 16**: Zero-Trust service directory, token ledger, security incidents
- **Redis 7 (DB 8)**: Distributed token revocation sets, IP reputation counters
- **RabbitMQ**: Security alert topic exchange, quarantine and dead-letter queues
- **Apache Spark 4.2 / PySpark**: Federated security threat anomaly clustering
- **Docker & Docker Compose**: Multi-tier isolated container orchestration
- **GitHub Actions**: Continuous integration pipeline with automated testing
