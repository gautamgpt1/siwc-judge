import hashlib
import io
import json
import os
import random
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from siwc_judge import api, auth, jwtlib, net, store


def fake(status, body=b"", headers=None):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    return net.Response(status, headers or {}, io.BytesIO(body))


def sse(*events):
    return fake(200, "".join(f"event: x\ndata: {json.dumps(e)}\n\n" for e in events).encode())


def completed(text="hi"):
    return [
        {"type": "response.output_text.delta", "delta": text},
        {"type": "response.completed", "response": {"model": "m", "usage": {"input_tokens": 1}}},
    ]


def _is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(rng, bits):
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(c):
            return c


_rng = random.Random(7)
_P, _Q = _prime(_rng, 512), _prime(_rng, 512)
_N, _E = _P * _Q, 65537
_D = pow(_E, -1, (_P - 1) * (_Q - 1))
JWK = {"kty": "RSA", "kid": "k1", "n": jwtlib.b64url_encode(_N.to_bytes(128, "big")),
       "e": jwtlib.b64url_encode(_E.to_bytes(3, "big"))}


def make_jwt(claims, alg="RS256"):
    h = jwtlib.b64url_encode(json.dumps({"alg": alg, "kid": "k1"}).encode())
    p = jwtlib.b64url_encode(json.dumps(claims).encode())
    k = 128
    t = jwtlib._SHA256_PREFIX + hashlib.sha256(f"{h}.{p}".encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), _D, _N).to_bytes(k, "big")
    return f"{h}.{p}.{jwtlib.b64url_encode(sig)}"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"SIWC_JUDGE_HOME": self.tmp.name})
        p.start()
        self.addCleanup(p.stop)


class PkceAndUrl(Base):
    def test_pkce_s256(self):
        v, c = auth.new_pkce()
        self.assertEqual(c, jwtlib.b64url_encode(hashlib.sha256(v.encode()).digest()))
        self.assertNotIn("=", c)

    def test_authorize_url_first_time(self):
        u = auth.build_authorize_url(client_id="dynamic_agent_client", host_id="urn:uuid:x",
                                     redirect_uri="http://127.0.0.1:1455/auth/callback", state="s", nonce="n",
                                     challenge="c")
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(u).query))
        self.assertEqual(q["client_id"], "dynamic_agent_client")
        self.assertEqual(q["agent_name_hint"], "siwc-judge")
        self.assertEqual(q["ext_agent_host_id"], "urn:uuid:x")
        self.assertEqual(q["scope"], "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct")
        self.assertEqual(q["resource"], "https://api.openai.com/v1")
        self.assertEqual(q["code_challenge_method"], "S256")
        self.assertEqual((q["state"], q["nonce"]), ("s", "n"))
        self.assertTrue(u.startswith("https://auth.openai.com/api/accounts/authorize?"))

    def test_authorize_url_reauth_omits_name_hint(self):
        u = auth.build_authorize_url(client_id="oaiapp_1", host_id="h", redirect_uri="r", state="s", nonce="n",
                                     challenge="c", reauth={"id_token": "T", "email": "a@b.c"})
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(u).query))
        self.assertNotIn("agent_name_hint", q)
        self.assertEqual((q["id_token_hint"], q["login_hint"]), ("T", "a@b.c"))

    def test_host_id_persisted(self):
        a = store.host_id()
        self.assertTrue(a.startswith("urn:uuid:"))
        self.assertEqual(a, store.host_id())


class Tokens(Base):
    def claims(self, **kw):
        c = {"iss": auth.ISSUER, "aud": "oaiapp_1", "exp": time.time() + 600, "nonce": "n", "sub": "u1",
             "email": "a@b.c"}
        c.update(kw)
        return c

    def test_id_token_valid_and_failures(self):
        jwks = {"keys": [JWK]}
        ok = jwtlib.validate_id_token(make_jwt(self.claims()), jwks, issuer=auth.ISSUER, audience="oaiapp_1",
                                      nonce="n", now=time.time())
        self.assertEqual(ok["sub"], "u1")
        for bad in (self.claims(nonce="x"), self.claims(aud="other"), self.claims(iss="evil"),
                    self.claims(exp=1)):
            with self.assertRaises(jwtlib.JwtError):
                jwtlib.validate_id_token(make_jwt(bad), jwks, issuer=auth.ISSUER, audience="oaiapp_1", nonce="n",
                                         now=time.time())
        tampered = make_jwt(self.claims())[:-4] + "AAAA"
        with self.assertRaises(jwtlib.JwtError):
            jwtlib.validate_id_token(tampered, jwks, issuer=auth.ISSUER, audience="oaiapp_1", nonce="n",
                                     now=time.time())

    def test_parse_token_response(self):
        t = auth.parse_token_response({"access_token": "a", "refresh_token": "r", "id_token": "i",
                                       "expires_in": 3600, "scope": "openid chatgpt.tokens.use.direct"}, now=100)
        self.assertEqual(t["expires_at"], 3700)
        self.assertIn(auth.PLAN_SCOPE, t["scopes"])
        with self.assertRaises(auth.AuthError):
            auth.parse_token_response({"access_token": "a"})

    def _login(self, scope):
        tok = {"access_token": "a", "refresh_token": "r", "id_token": make_jwt(self.claims()),
               "expires_in": 3600, "scope": scope}
        calls = []

        def send(method, url, headers=None, body=None, timeout=0):
            calls.append((method, url, body))
            if url == auth.TOKEN_URL:
                return fake(200, tok)
            return fake(200, {"keys": [JWK]})

        with mock.patch.object(net, "send", send):
            return auth.finish_login(client_id="oaiapp_1", host_id="h", code="c", verifier="v",
                                     redirect_uri="http://127.0.0.1:1/auth/callback", nonce="n", previous=None), calls

    def test_finish_login_saves_issued_client(self):
        rec, calls = self._login("openid email offline_access chatgpt.tokens.use.direct")
        saved = store.load()
        self.assertEqual(saved["client_id"], "oaiapp_1")
        self.assertTrue(saved["plan_usage_enabled"])
        body = dict(urllib.parse.parse_qsl(calls[0][2].decode()))
        self.assertEqual(body["client_id"], "oaiapp_1")
        self.assertEqual(body["resource"], "https://api.openai.com/v1")
        self.assertNotIn("client_secret", body)

    def test_finish_login_without_plan_scope(self):
        with self.assertRaises(auth.AuthError):
            self._login("openid email")
        self.assertFalse(store.load()["plan_usage_enabled"])

    def test_refresh_uses_issued_client_and_replaces_tokens(self):
        store.save({"client_id": "oaiapp_1", "refresh_token": "old", "access_token": "oa", "subject": "u1"})
        seen = {}

        def send(method, url, headers=None, body=None, timeout=0):
            seen.update(dict(urllib.parse.parse_qsl(body.decode())))
            return fake(200, {"access_token": "na", "refresh_token": "new", "expires_in": 3600, "scope": "openid"})

        with mock.patch.object(net, "send", send):
            rec = auth.refresh()
        self.assertEqual(seen["client_id"], "oaiapp_1")
        self.assertEqual(seen["grant_type"], "refresh_token")
        self.assertNotIn("scope", seen)
        self.assertEqual(store.load()["refresh_token"], "new")
        self.assertEqual(rec["access_token"], "na")

    def test_refresh_unusable(self):
        store.save({"client_id": "c", "refresh_token": "r"})
        with mock.patch.object(net, "send", lambda *a, **k: fake(400, {"error": "refresh_token_reused"})):
            with self.assertRaises(auth.AuthError) as cm:
                auth.refresh()
        self.assertIn("login", str(cm.exception))

    def test_logout_revokes_and_deletes(self):
        store.save({"client_id": "c", "refresh_token": "r"})
        posts = []

        def send(method, url, headers=None, body=None, timeout=0):
            if method == "GET":
                return fake(200, {"revocation_endpoint": "https://auth.openai.com/revoke"})
            posts.append(dict(urllib.parse.parse_qsl(body.decode())))
            return fake(200, b"")

        with mock.patch.object(net, "send", send):
            msg = auth.logout()
        self.assertEqual(posts[0]["token_type_hint"], "refresh_token")
        self.assertIsNone(store.load())
        self.assertIn("confirmed", msg)


class Sse(unittest.TestCase):
    def test_parse_completed(self):
        r = api.parse_sse(sse(*completed("hello")).iter_lines())
        self.assertEqual(r["output_text"], "hello")
        self.assertIsNone(r["error"])
        self.assertEqual(r["usage"], {"input_tokens": 1})

    def test_parse_failed_and_truncated(self):
        r = api.parse_sse(sse({"type": "response.failed", "response": {"error": {"code": "boom"}}}).iter_lines())
        self.assertEqual(r["error"]["code"], "boom")
        r = api.parse_sse(sse({"type": "response.output_text.delta", "delta": "x"}).iter_lines())
        self.assertEqual(r["error"]["code"], "stream_incomplete")

    def test_body_has_no_unsupported_fields(self):
        b = api.build_body("m", "ins", "hello")
        self.assertIs(b["store"], False)
        self.assertIs(b["stream"], True)
        self.assertEqual(b["input"], [{"role": "user", "content": "hello"}])
        self.assertFalse(set(b) & set(api.UNSUPPORTED_FIELDS))
        arr = [{"role": "user", "content": "x"}]
        self.assertEqual(api.build_body("m", "i", arr)["input"], arr)


class Run(Base):
    def setUp(self):
        super().setUp()
        store.save({"client_id": "c", "access_token": "tok", "refresh_token": "r", "expires_at": time.time() + 9999})
        self.inp = Path(self.tmp.name) / "in.jsonl"
        self.out = Path(self.tmp.name) / "out.jsonl"
        self.inp.write_text("\n".join(json.dumps({"id": i, "instructions": "I", "input": f"q{i}"})
                                      for i in ("a", "b")), encoding="utf-8")

    def run_cli(self, send, **kw):
        kw.setdefault("max_requests", None)
        with mock.patch.object(net, "send", send):
            return api.run(str(self.inp), str(self.out), model="m", cache_dir=str(Path(self.tmp.name) / "c"),
                           min_interval_s=0, log=lambda *_: None, **kw)

    def lines(self):
        return [json.loads(l) for l in self.out.read_text().splitlines()]

    def test_cache_skips_second_run_and_body_checked(self):
        bodies = []

        def send(method, url, headers=None, body=None, timeout=0):
            bodies.append(json.loads(body))
            self.assertEqual(headers["Authorization"], "Bearer tok")
            return sse(*completed("ok"))

        self.assertEqual(self.run_cli(send), 0)
        self.assertEqual(len(bodies), 2)
        for b in bodies:
            self.assertFalse(set(b) & set(api.UNSUPPORTED_FIELDS))
            self.assertEqual(set(b), {"model", "instructions", "input", "store", "stream"})
        self.assertEqual(self.lines()[0]["output_text"], "ok")
        self.assertEqual(self.run_cli(send), 0)
        self.assertEqual(len(bodies), 2)

    def test_usage_limit_stops_without_retry(self):
        n = []

        def send(*a, **k):
            n.append(1)
            return fake(429, {"error": {"code": "subscription_sharing_usage_limit_exceeded", "message": "m"}})

        self.assertEqual(self.run_cli(send), 3)
        self.assertEqual(len(n), 1)
        self.assertEqual(self.out.read_text(), "")

    def test_limit_as_response_failed_stops(self):
        def send(*a, **k):
            return sse({"type": "response.failed", "response": {"error": {
                "code": "subscription_sharing_usage_limit_exceeded"}}})

        self.assertEqual(self.run_cli(send), 3)

    def test_401_refreshes_once(self):
        seq = []

        def send(method, url, headers=None, body=None, timeout=0):
            if url == auth.TOKEN_URL:
                seq.append("refresh")
                return fake(200, {"access_token": "new", "refresh_token": "r2", "expires_in": 3600, "scope": "openid"})
            seq.append(headers["Authorization"])
            return fake(401, b"{}") if headers["Authorization"] == "Bearer tok" else sse(*completed())

        self.assertEqual(self.run_cli(send), 0)
        self.assertEqual(seq[:3], ["Bearer tok", "refresh", "Bearer new"])
        self.assertEqual(seq.count("refresh"), 1)

    def test_other_error_recorded_and_continues(self):
        def send(*a, **k):
            return fake(400, {"error": {"code": "subscription_sharing_unsupported_capability", "param": "x"}})

        self.assertEqual(self.run_cli(send), 0)
        self.assertEqual(self.lines()[0]["error"]["param"], "x")
        self.assertEqual(len(self.lines()), 2)

    def test_max_requests(self):
        self.assertEqual(self.run_cli(lambda *a, **k: sse(*completed()), max_requests=1), 3)
        self.assertEqual(len(self.lines()), 1)


if __name__ == "__main__":
    unittest.main()
