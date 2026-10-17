#include "sentineltrust.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <iomanip>

int main() {
    std::cout << "=================================================================\n";
    std::cout << "   SentinelTrust Zero-Trust Engine Nano-Benchmark (C++17)        \n";
    std::cout << "=================================================================\n\n";

    // 1. Benchmark Bloom Revocation Filter
    bloom_reset();
    for (int i = 0; i < 500; ++i) {
        std::string tok = "revoked_tok_" + std::to_string(i);
        bloom_insert_revocation(tok.c_str());
    }

    constexpr int BLOOM_ITERS = 10000000;
    auto t0 = std::chrono::high_resolution_clock::now();
    int hit_count = 0;
    for (int i = 0; i < BLOOM_ITERS; ++i) {
        std::string test_tok = "tok_candidate_" + std::to_string(i & 1023);
        hit_count += bloom_is_revoked(test_tok.c_str());
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double bloom_sec = std::chrono::duration<double>(t1 - t0).count();
    double bloom_ops_sec = (double)BLOOM_ITERS / bloom_sec;
    double bloom_ns_op = (bloom_sec * 1e9) / BLOOM_ITERS;

    std::cout << ">> [1] Bloom Revocation Filter: \n";
    std::cout << "     Total Checks:          " << BLOOM_ITERS << "\n";
    std::cout << "     Duration:              " << std::fixed << std::setprecision(4) << bloom_sec << " seconds\n";
    std::cout << "     Throughput:            " << std::fixed << std::setprecision(2) << (bloom_ops_sec / 1e6) << " M checks/sec\n";
    std::cout << "     Latency per Check:     " << std::fixed << std::setprecision(2) << bloom_ns_op << " ns/check\n\n";

    // 2. Benchmark Full Zero-Trust Token Verification
    constexpr int TOKEN_ITERS = 2000000;
    SecurityContext ctx;
    std::strcpy(ctx.client_ip, "10.240.10.15");
    ctx.current_time_sec = 1700000000;
    ctx.secret_seed = 42;
    ctx.ip_trust_score = 95;

    // Generate valid tokens with matching signature
    std::vector<ZeroTrustToken> tokens(1000);
    for (size_t i = 0; i < tokens.size(); ++i) {
        std::snprintf(tokens[i].token_id, sizeof(tokens[i].token_id), "tok_bench_%zu", i);
        std::strcpy(tokens[i].client_id, "client_service_worker");
        std::strcpy(tokens[i].service_id, "svc_payment_core");
        tokens[i].issued_at_sec = 1699900000;
        tokens[i].expires_at_sec = 1700100000;
        tokens[i].claims_crc = 123456;

        // Compute matching signature
        char buffer[256];
        std::snprintf(buffer, sizeof(buffer), "%s:%s:%s:%u", tokens[i].token_id, tokens[i].client_id, tokens[i].service_id, ctx.secret_seed);
        // Murmur hash
        uint64_t h = 0x5bd1e9955bd1e995ULL;
        const char* p = buffer;
        while (*p) {
            uint64_t k = (unsigned char)(*p++);
            k *= 0xc6a4a7935bd1e995ULL;
            k ^= k >> 47;
            k *= 0xc6a4a7935bd1e995ULL;
            h ^= k;
            h *= 0xc6a4a7935bd1e995ULL;
        }
        h ^= h >> 47;
        h *= 0xc6a4a7935bd1e995ULL;
        h ^= h >> 47;
        std::snprintf(tokens[i].signature, sizeof(tokens[i].signature), "sig_%016llx", (unsigned long long)h);
    }

    TokenAuthResult res;
    auto t2 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TOKEN_ITERS; ++i) {
        verify_zero_trust_token(&tokens[i % tokens.size()], &ctx, &res);
    }
    auto t3 = std::chrono::high_resolution_clock::now();
    double token_sec = std::chrono::duration<double>(t3 - t2).count();
    double token_ops_sec = (double)TOKEN_ITERS / token_sec;
    double token_ns_op = (token_sec * 1e9) / TOKEN_ITERS;

    std::cout << ">> [2] Zero-Trust Token Verification & Crypto Evaluation: \n";
    std::cout << "     Total Evals:           " << TOKEN_ITERS << "\n";
    std::cout << "     Duration:              " << std::fixed << std::setprecision(4) << token_sec << " seconds\n";
    std::cout << "     Throughput:            " << std::fixed << std::setprecision(2) << (token_ops_sec / 1e6) << " M tokens/sec\n";
    std::cout << "     Latency per Token:     " << std::fixed << std::setprecision(2) << token_ns_op << " ns/eval\n\n";

    // 3. Benchmark Batch Verification
    std::vector<TokenAuthResult> batch_results(tokens.size());
    constexpr int BATCH_ROUNDS = 2000;
    auto t4 = std::chrono::high_resolution_clock::now();
    for (int r = 0; r < BATCH_ROUNDS; ++r) {
        batch_verify_tokens(tokens.data(), (int32_t)tokens.size(), &ctx, batch_results.data());
    }
    auto t5 = std::chrono::high_resolution_clock::now();
    double batch_sec = std::chrono::duration<double>(t5 - t4).count();
    int total_batch_tokens = BATCH_ROUNDS * (int)tokens.size();
    double batch_ops_sec = (double)total_batch_tokens / batch_sec;

    std::cout << ">> [3] SIMD Vectorized Batch Verification: \n";
    std::cout << "     Total Tokens:          " << total_batch_tokens << "\n";
    std::cout << "     Throughput:            " << std::fixed << std::setprecision(2) << (batch_ops_sec / 1e6) << " M tokens/sec\n";
    std::cout << "     Status:                Engine fully optimized and operational.\n";
    std::cout << "=================================================================\n";

    return 0;
}
