#ifndef SENTINELTRUST_H
#define SENTINELTRUST_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 8)

typedef struct {
    char token_id[64];
    char client_id[64];
    char service_id[64];
    int64_t issued_at_sec;
    int64_t expires_at_sec;
    uint32_t claims_crc;
    char signature[64];
} ZeroTrustToken;

typedef struct {
    char client_ip[64];
    int64_t current_time_sec;
    uint32_t secret_seed;
    int32_t ip_trust_score; // 0 (hostile) to 100 (trusted)
} SecurityContext;

typedef struct {
    int32_t auth_decision;    // 0: ALLOWED, 1: DENIED_REVOKED, 2: DENIED_EXPIRED, 3: DENIED_TAMPERED, 4: DENIED_ANOMALY
    double threat_score;      // 0.0 to 100.0
    int32_t latency_ns;
    char reason[128];
} TokenAuthResult;

#pragma pack(pop)

// Core Verification API
void verify_zero_trust_token(const ZeroTrustToken* token, const SecurityContext* ctx, TokenAuthResult* out_result);

// Batch SIMD Vectorized Verification
void batch_verify_tokens(const ZeroTrustToken* tokens, int32_t count, const SecurityContext* ctx, TokenAuthResult* out_results);

// Ultra-fast In-Memory Bloom Revocation Filter
void bloom_insert_revocation(const char* token_id);
int32_t bloom_is_revoked(const char* token_id);
void bloom_reset();

#ifdef __cplusplus
}
#endif

#endif // SENTINELTRUST_H
