"""Stdlib-only RS256 JWT verification (PKCS#1 v1.5 / SHA-256)."""
from __future__ import annotations

import base64
import hashlib
import json

_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class JwtError(Exception):
    pass


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def decode_unverified(token: str) -> tuple[dict, dict, bytes, bytes]:
    try:
        h, p, s = token.split(".")
        header, claims = json.loads(b64url_decode(h)), json.loads(b64url_decode(p))
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ValueError("not a JSON object")
        return header, claims, b64url_decode(s), f"{h}.{p}".encode("ascii")
    except Exception as exc:
        raise JwtError("malformed JWT") from exc


def verify_rs256(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    k = (n.bit_length() + 7) // 8
    s = int.from_bytes(signature, "big")
    if len(signature) != k or s >= n:  # RFC 8017 RSAVP1: representative must be < n
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expected


def validate_id_token(
    token: str, jwks: dict, *, issuer: str, audience: str, nonce: str, now: float, leeway: int = 60
) -> dict:
    header, claims, sig, signing_input = decode_unverified(token)
    if header.get("alg") != "RS256":
        raise JwtError("unsupported alg")
    keys = [
        k
        for k in jwks.get("keys", [])
        if k.get("kty") == "RSA" and k.get("alg") in (None, "RS256") and k.get("use") in (None, "sig")
        and (not header.get("kid") or k.get("kid") == header.get("kid"))
    ]

    def ok(k):
        try:
            return verify_rs256(signing_input, sig, k)
        except (KeyError, ValueError, TypeError):
            return False

    if not any(ok(k) for k in keys):
        raise JwtError("signature verification failed")
    if claims.get("iss") != issuer:
        raise JwtError("issuer mismatch")
    aud = claims.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise JwtError("audience mismatch")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - leeway:
        raise JwtError("ID token expired")
    if claims.get("nonce") != nonce:
        raise JwtError("nonce mismatch")
    if not claims.get("sub"):
        raise JwtError("missing sub")
    return claims
