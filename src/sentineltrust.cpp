#include "sentineltrust.h"
#include <cstring>
#include <cstdio>
#include <chrono>
#include <algorithm>
#include <vector>

// 65536-bit Bloom Filter (8KB bitset)
constexpr size_t BLOOM_BITS = 65536;
constexpr size_t BLOOM_BYTES = BLOOM_BITS / 8;
static uint8_t g_bloom_filter[BLOOM_BYTES] = {0};

// Hash Function 1: FNV-1a 64-bit
static inline uint64_t hash_fnv1a(const char* str) {
    uint64_t hash = 14695981039346656037ULL;
    while (*str) {
        hash ^= (uint64_t)(unsigned char)(*str++);
        hash *= 1099511628211ULL;
    }
    return hash;
}

// Hash Function 2: Murmur-style 64-bit mixer
static inline uint64_t hash_murmur(const char* str) {
    uint64_t h = 0x5bd1e9955bd1e995ULL;
    while (*str) {
        uint64_t k = (unsigned char)(*str++);
        k *= 0xc6a4a7935bd1e995ULL;
        k ^= k >> 47;
        k *= 0xc6a4a7935bd1e995ULL;
        h ^= k;
        h *= 0xc6a4a7935bd1e995ULL;
    }
    h ^= h >> 47;
    h *= 0xc6a4a7935bd1e995ULL;
    h ^= h >> 47;
    return h;
}

// Hash Function 3: Jenkins 32-bit mixer
static inline uint32_t hash_jenkins(const char* str) {
    uint32_t hash = 0;
    while (*str) {
        hash += (unsigned char)(*str++);
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

extern "C" {

void bloom_insert_revocation(const char* token_id) {
    if (!token_id) return;
    uint64_t h1 = hash_fnv1a(token_id) % BLOOM_BITS;
    uint64_t h2 = hash_murmur(token_id) % BLOOM_BITS;
    uint64_t h3 = ((uint64_t)hash_jenkins(token_id)) % BLOOM_BITS;

    g_bloom_filter[h1 / 8] |= (1 << (h1 % 8));
    g_bloom_filter[h2 / 8] |= (1 << (h2 % 8));
    g_bloom_filter[h3 / 8] |= (1 << (h3 % 8));
}

int32_t bloom_is_revoked(const char* token_id) {
    if (!token_id) return 0;
    uint64_t h1 = hash_fnv1a(token_id) % BLOOM_BITS;
    if (!(g_bloom_filter[h1 / 8] & (1 << (h1 % 8)))) return 0;

    uint64_t h2 = hash_murmur(token_id) % BLOOM_BITS;
    if (!(g_bloom_filter[h2 / 8] & (1 << (h2 % 8)))) return 0;

    uint64_t h3 = ((uint64_t)hash_jenkins(token_id)) % BLOOM_BITS;
    if (!(g_bloom_filter[h3 / 8] & (1 << (h3 % 8)))) return 0;

    return 1; // Likely revoked (Bloom hit)
}

void bloom_reset() {
    std::memset(g_bloom_filter, 0, BLOOM_BYTES);
}

void verify_zero_trust_token(const ZeroTrustToken* token, const SecurityContext* ctx, TokenAuthResult* out_result) {
    if (!token || !ctx || !out_result) return;

    auto t_start = std::chrono::high_resolution_clock::now();

    // 1. Instant Bloom Revocation Gate
    if (bloom_is_revoked(token->token_id)) {
        out_result->auth_decision = 1; // DENIED_REVOKED
        out_result->threat_score = 95.0;
        std::snprintf(out_result->reason, sizeof(out_result->reason), "Token %s is in active revocation Bloom filter", token->token_id);
        auto t_end = std::chrono::high_resolution_clock::now();
        out_result->latency_ns = (int32_t)std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count();
        return;
    }

    // 2. Expiration Check
    if (ctx->current_time_sec > token->expires_at_sec) {
        out_result->auth_decision = 2; // DENIED_EXPIRED
        out_result->threat_score = 65.0;
        std::snprintf(out_result->reason, sizeof(out_result->reason), "Token expired at %lld (current %lld)", (long long)token->expires_at_sec, (long long)ctx->current_time_sec);
        auto t_end = std::chrono::high_resolution_clock::now();
        out_result->latency_ns = (int32_t)std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count();
        return;
    }

    // 3. Cryptographic Signature Integrity Check
    // Expected signature: hex of hash(token_id + client_id + service_id + secret_seed)
    char buffer[256];
    int len = std::snprintf(buffer, sizeof(buffer), "%s:%s:%s:%u", token->token_id, token->client_id, token->service_id, ctx->secret_seed);
    uint64_t exp_hash = hash_murmur(buffer);
    char exp_sig[64];
    std::snprintf(exp_sig, sizeof(exp_sig), "sig_%016llx", (unsigned long long)exp_hash);

    if (std::strcmp(token->signature, exp_sig) != 0) {
        out_result->auth_decision = 3; // DENIED_TAMPERED
        out_result->threat_score = 99.5;
        std::snprintf(out_result->reason, sizeof(out_result->reason), "Signature mismatch: potential cryptographic tampering");
        auto t_end = std::chrono::high_resolution_clock::now();
        out_result->latency_ns = (int32_t)std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count();
        return;
    }

    // 4. IP Threat / Reputation Anomaly Scoring
    double base_score = 0.0;
    if (ctx->ip_trust_score < 40) {
        base_score += (40 - ctx->ip_trust_score) * 1.5;
    }

    if (base_score >= 50.0) {
        out_result->auth_decision = 4; // DENIED_ANOMALY
        out_result->threat_score = base_score;
        std::snprintf(out_result->reason, sizeof(out_result->reason), "Untrusted IP / hostile source anomaly (reputation: %d)", ctx->ip_trust_score);
    } else {
        out_result->auth_decision = 0; // ALLOWED
        out_result->threat_score = base_score;
        std::snprintf(out_result->reason, sizeof(out_result->reason), "Token verified and authorized");
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    out_result->latency_ns = (int32_t)std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count();
}

void batch_verify_tokens(const ZeroTrustToken* tokens, int32_t count, const SecurityContext* ctx, TokenAuthResult* out_results) {
    if (!tokens || !ctx || !out_results || count <= 0) return;

    int32_t i = 0;
    for (; i <= count - 4; i += 4) {
        verify_zero_trust_token(&tokens[i], ctx, &out_results[i]);
        verify_zero_trust_token(&tokens[i+1], ctx, &out_results[i+1]);
        verify_zero_trust_token(&tokens[i+2], ctx, &out_results[i+2]);
        verify_zero_trust_token(&tokens[i+3], ctx, &out_results[i+3]);
    }
    for (; i < count; ++i) {
        verify_zero_trust_token(&tokens[i], ctx, &out_results[i]);
    }
}

}
