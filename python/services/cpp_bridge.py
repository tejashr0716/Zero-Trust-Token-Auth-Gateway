import ctypes
import os
from typing import List, Dict, Any, Optional

class CZeroTrustToken(ctypes.Structure):
    _layout_ = "ms"
    _pack_ = 8
    _fields_ = [
        ("token_id", ctypes.c_char * 64),
        ("client_id", ctypes.c_char * 64),
        ("service_id", ctypes.c_char * 64),
        ("issued_at_sec", ctypes.c_int64),
        ("expires_at_sec", ctypes.c_int64),
        ("claims_crc", ctypes.c_uint32),
        ("signature", ctypes.c_char * 64)
    ]

class CSecurityContext(ctypes.Structure):
    _layout_ = "ms"
    _pack_ = 8
    _fields_ = [
        ("client_ip", ctypes.c_char * 64),
        ("current_time_sec", ctypes.c_int64),
        ("secret_seed", ctypes.c_uint32),
        ("ip_trust_score", ctypes.c_int32)
    ]

class CTokenAuthResult(ctypes.Structure):
    _layout_ = "ms"
    _pack_ = 8
    _fields_ = [
        ("auth_decision", ctypes.c_int32),
        ("threat_score", ctypes.c_double),
        ("latency_ns", ctypes.c_int32),
        ("reason", ctypes.c_char * 128)
    ]

DECISION_NAMES = {
    0: "ALLOWED",
    1: "DENIED_REVOKED",
    2: "DENIED_EXPIRED",
    3: "DENIED_TAMPERED",
    4: "DENIED_ANOMALY"
}

class SentinelTrustEngine:
    def __init__(self, dylib_path: Optional[str] = None):
        if dylib_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            dylib_path = os.path.join(base_dir, "libsentineltrust.dylib")

        if not os.path.exists(dylib_path):
            raise FileNotFoundError(f"Shared library not found at: {dylib_path}")

        self.lib = ctypes.CDLL(dylib_path)

        # void verify_zero_trust_token(...)
        self.lib.verify_zero_trust_token.argtypes = [
            ctypes.POINTER(CZeroTrustToken),
            ctypes.POINTER(CSecurityContext),
            ctypes.POINTER(CTokenAuthResult)
        ]
        self.lib.verify_zero_trust_token.restype = None

        # void batch_verify_tokens(...)
        self.lib.batch_verify_tokens.argtypes = [
            ctypes.POINTER(CZeroTrustToken),
            ctypes.c_int32,
            ctypes.POINTER(CSecurityContext),
            ctypes.POINTER(CTokenAuthResult)
        ]
        self.lib.batch_verify_tokens.restype = None

        # Bloom API
        self.lib.bloom_insert_revocation.argtypes = [ctypes.c_char_p]
        self.lib.bloom_insert_revocation.restype = None

        self.lib.bloom_is_revoked.argtypes = [ctypes.c_char_p]
        self.lib.bloom_is_revoked.restype = ctypes.c_int32

        self.lib.bloom_reset.argtypes = []
        self.lib.bloom_reset.restype = None

    def compute_signature(self, token_id: str, client_id: str, service_id: str, secret_seed: int = 42) -> str:
        # Replicates Murmur 64-bit mixer from C++ engine
        buffer = f"{token_id}:{client_id}:{service_id}:{secret_seed}".encode("utf-8")
        h = 0x5bd1e9955bd1e995
        for b in buffer:
            k = (b * 0xc6a4a7935bd1e995) & 0xFFFFFFFFFFFFFFFF
            k ^= (k >> 47)
            k = (k * 0xc6a4a7935bd1e995) & 0xFFFFFFFFFFFFFFFF
            h ^= k
            h = (h * 0xc6a4a7935bd1e995) & 0xFFFFFFFFFFFFFFFF
        h ^= (h >> 47)
        h = (h * 0xc6a4a7935bd1e995) & 0xFFFFFFFFFFFFFFFF
        h ^= (h >> 47)
        return f"sig_{h:016x}"

    def verify_token(
        self,
        token_id: str,
        client_id: str,
        service_id: str,
        issued_at_sec: int,
        expires_at_sec: int,
        signature: str,
        client_ip: str = "10.0.0.1",
        current_time_sec: int = 0,
        secret_seed: int = 42,
        ip_trust_score: int = 90
    ) -> Dict[str, Any]:
        tok = CZeroTrustToken(
            token_id=token_id.encode("utf-8"),
            client_id=client_id.encode("utf-8"),
            service_id=service_id.encode("utf-8"),
            issued_at_sec=issued_at_sec,
            expires_at_sec=expires_at_sec,
            claims_crc=0,
            signature=signature.encode("utf-8")
        )
        ctx = CSecurityContext(
            client_ip=client_ip.encode("utf-8"),
            current_time_sec=current_time_sec,
            secret_seed=secret_seed,
            ip_trust_score=ip_trust_score
        )
        res = CTokenAuthResult()
        self.lib.verify_zero_trust_token(ctypes.byref(tok), ctypes.byref(ctx), ctypes.byref(res))

        return {
            "decision_code": res.auth_decision,
            "decision": DECISION_NAMES.get(res.auth_decision, "UNKNOWN"),
            "threat_score": round(res.threat_score, 2),
            "latency_ns": res.latency_ns,
            "reason": res.reason.decode("utf-8")
        }

    def batch_verify(self, tokens_list: List[Dict[str, Any]], ctx_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        n = len(tokens_list)
        if n == 0:
            return []

        tok_arr = (CZeroTrustToken * n)()
        res_arr = (CTokenAuthResult * n)()

        for i, item in enumerate(tokens_list):
            tok_arr[i] = CZeroTrustToken(
                token_id=str(item.get("token_id", "")).encode("utf-8"),
                client_id=str(item.get("client_id", "")).encode("utf-8"),
                service_id=str(item.get("service_id", "")).encode("utf-8"),
                issued_at_sec=int(item.get("issued_at_sec", 0)),
                expires_at_sec=int(item.get("expires_at_sec", 0)),
                claims_crc=0,
                signature=str(item.get("signature", "")).encode("utf-8")
            )

        ctx = CSecurityContext(
            client_ip=str(ctx_dict.get("client_ip", "10.0.0.1")).encode("utf-8"),
            current_time_sec=int(ctx_dict.get("current_time_sec", 0)),
            secret_seed=int(ctx_dict.get("secret_seed", 42)),
            ip_trust_score=int(ctx_dict.get("ip_trust_score", 90))
        )

        self.lib.batch_verify_tokens(tok_arr, n, ctypes.byref(ctx), res_arr)

        output = []
        for i in range(n):
            output.append({
                "decision_code": res_arr[i].auth_decision,
                "decision": DECISION_NAMES.get(res_arr[i].auth_decision, "UNKNOWN"),
                "threat_score": round(res_arr[i].threat_score, 2),
                "latency_ns": res_arr[i].latency_ns,
                "reason": res_arr[i].reason.decode("utf-8")
            })
        return output

    def bloom_add(self, token_id: str):
        self.lib.bloom_insert_revocation(token_id.encode("utf-8"))

    def bloom_contains(self, token_id: str) -> bool:
        return bool(self.lib.bloom_is_revoked(token_id.encode("utf-8")))

    def bloom_clear(self):
        self.lib.bloom_reset()
