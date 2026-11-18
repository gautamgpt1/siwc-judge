import contextlib
import hashlib
import http.client
import http.server
import io
import json
import os
import random
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

from siwc_judge import api, auth, jwtlib, net, store

PLAN_SCOPES = sorted(auth.SCOPES.split())


def fake(status, body=b"", headers=None):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    return net.Response(status, headers or {}, io.BytesIO(body))


def sse(*events, headers=None):
    return fake(200, "".join(f"event: x\ndata: {json.dumps(e)}\n\n" for e in events).encode(), headers)


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


def _sign(signing_input: bytes) -> bytes:
    t = jwtlib._SHA256_PREFIX + hashlib.sha256(signing_input).digest()
    em = b"\x00\x01" + b"\xff" * (128 - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), _D, _N).to_bytes(128, "big")


def make_jwt(claims, alg="RS256"):
    h = jwtlib.b64url_encode(json.dumps({"alg": alg, "kid": "k1"}).encode())
    p = jwtlib.b64url_encode(json.dumps(claims).encode())
    return f"{h}.{p}.{jwtlib.b64url_encode(_sign(f'{h}.{p}'.encode()))}"


def claims(**kw):
    c = {"iss": auth.ISSUER, "aud": "oaiapp_1", "exp": time.time() + 600, "nonce": "n", "sub": "u1",
         "email": "a@b.c"}
    c.update(kw)
    return c


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
        self.assertNotIn("prompt", q)
        self.assertTrue(u.startswith("https://auth.openai.com/api/accounts/authorize?"))

    def test_authorize_url_reauth_omits_name_hint(self):
        u = auth.build_authorize_url(client_id="oaiapp_1", host_id="h", redirect_uri="r", state="s", nonce="n",
                                     challenge="c", reauth={"id_token": "T", "email": "a@b.c"})
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(u).query))
        self.assertNotIn("agent_name_hint", q)
        self.assertEqual((q["id_token_hint"], q["login_hint"]), ("T", "a@b.c"))

    def test_authorize_url_after_signout_and_consent(self):
        u = auth.build_authorize_url(client_id="oaiapp_1", host_id="h", redirect_uri="r", state="s", nonce="n",
                                     challenge="c", reauth={"email": "a@b.c"}, consent=True)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(u).query))
        self.assertNotIn("id_token_hint", q)
        self.assertEqual((q["login_hint"], q["prompt"]), ("a@b.c", "consent"))

    def test_host_id_persisted(self):
        a = store.host_id()
        self.assertTrue(a.startswith("urn:uuid:"))
        self.assertEqual(a, store.host_id())


class Jwt(unittest.TestCase):
    def test_id_token_valid_and_failures(self):
        jwks = {"keys": [JWK]}
        ok = jwtlib.validate_id_token(make_jwt(claims()), jwks, issuer=auth.ISSUER, audience="oaiapp_1",
                                      nonce="n", now=time.time())
        self.assertEqual(ok["sub"], "u1")
        for bad in (claims(nonce="x"), claims(aud="other"), claims(iss="evil"), claims(exp=1), claims(sub="")):
            with self.assertRaises(jwtlib.JwtError):
                jwtlib.validate_id_token(make_jwt(bad), jwks, issuer=auth.ISSUER, audience="oaiapp_1", nonce="n",
                                         now=time.time())
        for token in (make_jwt(claims())[:-4] + "AAAA", make_jwt(claims(), alg="HS256"), "x.y"):
            with self.assertRaises(jwtlib.JwtError):
                jwtlib.validate_id_token(token, jwks, issuer=auth.ISSUER, audience="oaiapp_1", nonce="n",
                                         now=time.time())
        with self.assertRaises(jwtlib.JwtError):  # an encryption key is not a signing key
            jwtlib.validate_id_token(make_jwt(claims()), {"keys": [dict(JWK, use="enc")]}, issuer=auth.ISSUER,
                                     audience="oaiapp_1", nonce="n", now=time.time())

    def test_signature_representative_must_be_below_modulus(self):
        for i in range(200):
            msg = f"m{i}".encode()
            s = int.from_bytes(_sign(msg), "big")
            if s + _N < 256 ** 128:
                break
        self.assertTrue(jwtlib.verify_rs256(msg, s.to_bytes(128, "big"), JWK))
        self.assertFalse(jwtlib.verify_rs256(msg, (s + _N).to_bytes(128, "big"), JWK))


class Tokens(Base):
    def _login(self, scope):
        tok = {"access_token": "a", "refresh_token": "r", "id_token": make_jwt(claims()),
               "expires_in": 3600, "scope": scope, "earliest_refresh_at": 123}
        calls = []

        def send(method, url, headers=None, body=None, timeout=0):
            calls.append((method, url, body))
            if url == auth.TOKEN_URL:
                return fake(200, tok)
            return fake(200, {"keys": [JWK]})

        with mock.patch.object(net, "send", send):
            return auth.finish_login(client_id="oaiapp_1", host_id="h", code="c", verifier="v",
                                     redirect_uri="http://127.0.0.1:1/auth/callback", nonce="n", previous=None), calls

    def test_parse_token_response(self):
        t = auth.parse_token_response({"access_token": "a", "refresh_token": "r", "id_token": "i",
                                       "expires_in": 3600, "scope": "openid chatgpt.tokens.use.direct"}, now=100)
        self.assertEqual(t["expires_at"], 3700)
        self.assertIn(auth.PLAN_SCOPE, t["scopes"])
        self.assertIsNone(auth.parse_token_response({"access_token": "a", "refresh_token": "r"})["scopes"])
        with self.assertRaises(auth.AuthError):
            auth.parse_token_response({"access_token": "a"})

    def test_finish_login_saves_issued_client(self):
        rec, calls = self._login("openid email offline_access chatgpt.tokens.use.direct")
        saved = store.load()
        self.assertEqual(saved["client_id"], "oaiapp_1")
        self.assertTrue(saved["plan_usage_enabled"])
        self.assertEqual(saved["earliest_refresh_at"], 123)
        body = dict(urllib.parse.parse_qsl(calls[0][2].decode()))
        self.assertEqual(body["client_id"], "oaiapp_1")
        self.assertEqual(body["resource"], "https://api.openai.com/v1")
        self.assertNotIn("client_secret", body)

    def test_finish_login_without_plan_scope(self):
        with self.assertRaises(auth.AuthError) as cm:
            self._login("openid email")
        self.assertIn("--consent", str(cm.exception))
        self.assertFalse(store.load()["plan_usage_enabled"])

    def test_refresh_uses_issued_client_and_replaces_tokens(self):
        store.save({"client_id": "oaiapp_1", "refresh_token": "old", "access_token": "oa", "subject": "u1",
                    "scopes": PLAN_SCOPES, "earliest_refresh_at": 5})
        seen = {}

        def send(method, url, headers=None, body=None, timeout=0):
            seen.update(dict(urllib.parse.parse_qsl(body.decode())))
            return fake(200, {"access_token": "na", "refresh_token": "new", "expires_in": 3600})

        with mock.patch.object(net, "send", send):
            rec = auth.refresh()
        self.assertEqual(seen["client_id"], "oaiapp_1")
        self.assertEqual(seen["grant_type"], "refresh_token")
        self.assertEqual(seen["resource"], "https://api.openai.com/v1")
        self.assertNotIn("scope", seen)
        saved = store.load()
        self.assertEqual(saved["refresh_token"], "new")
        self.assertEqual(saved["scopes"], PLAN_SCOPES)  # omitted scope keeps the grant
        self.assertNotIn("earliest_refresh_at", saved)
        self.assertEqual(rec["access_token"], "na")

    def test_refresh_adopts_tokens_rotated_by_another_process(self):
        store.save({"client_id": "c", "access_token": "new", "refresh_token": "r2", "expires_at": time.time() + 3000})
        with mock.patch.object(net, "send", side_effect=AssertionError("no network expected")):
            rec = auth.refresh({"client_id": "c", "access_token": "old", "refresh_token": "r1"}, rejected="old")
        self.assertEqual(rec["access_token"], "new")

    def test_refresh_unusable_clears_tokens_keeps_registration(self):
        store.save({"client_id": "c", "refresh_token": "r", "access_token": "a", "id_token": "i", "subject": "u1"})
        with mock.patch.object(net, "send", lambda *a, **k: fake(400, {"error": "refresh_token_reused"})):
            with self.assertRaises(auth.AuthError) as cm:
                auth.refresh()
        self.assertIn("login", str(cm.exception))
        saved = store.load()
        self.assertEqual((saved["client_id"], saved["id_token"], saved["subject"]), ("c", "i", "u1"))
        self.assertNotIn("refresh_token", saved)
        self.assertNotIn("access_token", saved)

    def test_refresh_transient_failure_keeps_tokens(self):
        store.save({"client_id": "c", "refresh_token": "r", "access_token": "a"})
        with mock.patch.object(net, "send", lambda *a, **k: fake(502, b"bad gateway")):
            with self.assertRaises(auth.AuthError):
                auth.refresh()
        self.assertEqual(store.load()["refresh_token"], "r")

    def test_ensure_fresh_honours_earliest_refresh_at(self):
        now = time.time()
        rec = {"client_id": "c", "access_token": "a", "refresh_token": "r", "expires_at": now + 60,
               "earliest_refresh_at": now + 30}
        with mock.patch.object(net, "send", side_effect=AssertionError("no refresh expected")):
            self.assertIs(auth.ensure_fresh(rec), rec)

    def test_logout_revokes_clears_tokens_keeps_registration(self):
        store.save({"client_id": "c", "refresh_token": "r", "access_token": "a", "id_token": "i",
                    "subject": "u1", "email": "a@b.c"})
        host = store.host_id()
        posts = []

        def send(method, url, headers=None, body=None, timeout=0):
            if method == "GET":
                return fake(200, {"revocation_endpoint": "https://auth.openai.com/oauth/revoke"})
            posts.append(dict(urllib.parse.parse_qsl(body.decode())))
            return fake(200, b"")

        with mock.patch.object(net, "send", send):
            msg = auth.logout()
        self.assertEqual(posts, [{"token": "r", "token_type_hint": "refresh_token", "client_id": "c"}])
        self.assertIn("confirmed", msg)
        saved = store.load()
        self.assertEqual((saved["client_id"], saved["subject"], saved["email"]), ("c", "u1", "a@b.c"))
        for k in ("access_token", "refresh_token", "id_token"):
            self.assertNotIn(k, saved)
        self.assertEqual(store.host_id(), host)
        with self.assertRaises(api.StopRun):
            api._need_creds()

    def test_logout_untrusted_endpoint_and_forget(self):
        store.save({"client_id": "c", "refresh_token": "r"})
        posts = []

        def send(method, url, headers=None, body=None, timeout=0):
            if method == "GET":
                return fake(200, {"revocation_endpoint": "https://auth.openai.com.evil.example/revoke"})
            posts.append(url)
            return fake(200, b"")

        with mock.patch.object(net, "send", send):
            msg = auth.logout(forget=True)
        self.assertEqual(posts, [])
        self.assertIn("NOT confirmed", msg)
        self.assertIsNone(store.load())

    def test_logout_retries_network_failure(self):
        store.save({"client_id": "c", "refresh_token": "r"})
        n = []

        def send(method, url, headers=None, body=None, timeout=0):
            if method == "GET":
                return fake(200, {"revocation_endpoint": "https://auth.openai.com/oauth/revoke"})
            n.append(1)
            if len(n) == 1:
                raise urllib.error.URLError("down")
            return fake(200, b"")

        with mock.patch.object(net, "send", send), mock.patch.object(time, "sleep"):
            self.assertIn("revocation confirmed", auth.logout())
        self.assertEqual(len(n), 2)


class LoginFlow(Base):
    """Drives login() through the real loopback listener; only OpenAI's endpoints are faked."""

    def run_login(self, previous=None, scope=auth.SCOPES, issued="oaiapp_1", sub="u1", **kw):
        if previous:
            store.save(previous)
        seen = {}

        def get(port, path):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", path)
            r = c.getresponse()
            r.read()
            c.close()
            return r.status

        def browse(url):
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            seen["q"] = q
            port = urllib.parse.urlparse(q["redirect_uri"]).port
            seen["wrong_state"] = get(port, "/auth/callback?state=wrong&code=evil&client_id=oaiapp_evil")
            seen["other_path"] = get(port, "/favicon.ico")
            cb = f"/auth/callback?state={urllib.parse.quote(q['state'])}&code=c1"
            seen["ok"] = get(port, cb + (f"&client_id={issued}" if issued else ""))

        def send(method, url, headers=None, body=None, timeout=0):
            if url == auth.TOKEN_URL:
                seen["exchange"] = dict(urllib.parse.parse_qsl(body.decode()))
                return fake(200, {"access_token": "a", "refresh_token": "r", "expires_in": 3600, "scope": scope,
                                  "id_token": make_jwt(claims(nonce=seen["q"]["nonce"], sub=sub))})
            return fake(200, {"keys": [JWK]})

        out = io.StringIO()
        with mock.patch.object(auth, "DEFAULT_PORT", 0), mock.patch.object(net, "send", send), \
                contextlib.redirect_stdout(out):
            try:
                seen["record"] = auth.login(open_browser=browse, timeout=10, **kw)
            except auth.AuthError as e:
                seen["error"] = str(e)
        seen["stdout"] = out.getvalue()
        return seen

    def test_first_registration(self):
        s = self.run_login()
        self.assertEqual((s["wrong_state"], s["other_path"], s["ok"]), (400, 404, 200))
        self.assertEqual(s["q"]["client_id"], "dynamic_agent_client")
        self.assertEqual(s["q"]["ext_agent_host_id"], store.host_id())
        self.assertTrue(s["q"]["redirect_uri"].startswith("http://127.0.0.1:"))
        self.assertEqual(s["exchange"]["client_id"], "oaiapp_1")
        self.assertEqual(s["exchange"]["code"], "c1")  # the wrong-state code was never used
        self.assertEqual(s["exchange"]["redirect_uri"], s["q"]["redirect_uri"])
        self.assertEqual(store.load()["client_id"], "oaiapp_1")
        self.assertTrue(store.load()["plan_usage_enabled"])

    def test_registration_without_issued_client(self):
        s = self.run_login(issued=None)
        self.assertIn("registration incomplete", s["error"])

    def test_reauth_uses_saved_client_and_hides_hint(self):
        prev = {"client_id": "oaiapp_1", "subject": "u1", "email": "a@b.c", "id_token": "SECRET.ID.TOKEN",
                "plan_usage_enabled": True}
        s = self.run_login(previous=prev, issued=None)
        self.assertNotIn("error", s)
        self.assertEqual((s["q"]["client_id"], s["q"]["id_token_hint"]), ("oaiapp_1", "SECRET.ID.TOKEN"))
        self.assertNotIn("agent_name_hint", s["q"])
        self.assertNotIn("prompt", s["q"])
        self.assertNotIn("SECRET", s["stdout"])

    def test_reauth_rejects_other_account_and_other_client(self):
        prev = {"client_id": "oaiapp_1", "subject": "u1", "access_token": "keep", "plan_usage_enabled": True}
        self.assertIn("differs from the saved account", self.run_login(previous=prev, sub="u2")["error"])
        self.assertIn("client_id differs", self.run_login(previous=prev, issued="oaiapp_2")["error"])
        self.assertEqual(store.load()["access_token"], "keep")

    def test_declined_plan_scope_reasks_consent(self):
        prev = {"client_id": "oaiapp_1", "subject": "u1", "plan_usage_enabled": False}
        self.assertEqual(self.run_login(previous=prev, issued=None)["q"]["prompt"], "consent")

    def test_listener_falls_back_when_port_busy(self):
        busy = socket.socket()  # like another Python HTTPServer login listener; Windows would let us double-bind
        busy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        self.addCleanup(busy.close)
        with mock.patch.object(auth, "DEFAULT_PORT", busy.getsockname()[1]):
            srv = auth._listen("s")
        self.addCleanup(srv.server_close)
        self.assertNotEqual(srv.server_address[1], busy.getsockname()[1])
        self.assertEqual(srv.server_address[0], "127.0.0.1")


class Redirects(unittest.TestCase):
    def test_bearer_token_never_follows_a_redirect(self):
        hits = []

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        target = http.server.HTTPServer(("127.0.0.1", 0), Target)

        class Hop(Target):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target.server_address[1]}/steal")
                self.end_headers()

        hop = http.server.HTTPServer(("127.0.0.1", 0), Hop)
        for s in (target, hop):
            threading.Thread(target=s.serve_forever, daemon=True).start()
            self.addCleanup(s.server_close)
            self.addCleanup(s.shutdown)
        r = net.send("GET", f"http://127.0.0.1:{hop.server_address[1]}/", {"Authorization": "Bearer t"}, timeout=5)
        r.read()
        self.assertEqual(r.status, 302)
        self.assertEqual(hits, [])


class Sse(unittest.TestCase):
    def test_parse_completed(self):
        r = api.parse_sse(sse(*completed("hello")).iter_lines())
        self.assertEqual(r["output_text"], "hello")
        self.assertIsNone(r["error"])
        self.assertEqual(r["usage"], {"input_tokens": 1})

    def test_text_done_fallback(self):
        r = api.parse_sse(sse({"type": "response.output_text.done", "text": "whole"},
                              {"type": "response.completed", "response": {"output": []}}).iter_lines())
        self.assertEqual(r["output_text"], "whole")

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
        self.assertNotIn("instructions", api.build_body("m", None, "x"))


class Run(Base):
    def setUp(self):
        super().setUp()
        store.save({"client_id": "c", "access_token": "tok", "refresh_token": "r", "expires_at": time.time() + 9999,
                    "scopes": PLAN_SCOPES})
        self.inp = Path(self.tmp.name) / "in.jsonl"
        self.out = Path(self.tmp.name) / "out.jsonl"
        self.inp.write_text("\n".join(json.dumps({"id": i, "instructions": "I", "input": f"q{i}"})
                                      for i in ("a", "b")), encoding="utf-8")

    def run_cli(self, send, **kw):
        kw.setdefault("max_requests", None)
        kw.setdefault("model", "m")
        with mock.patch.object(net, "send", send):
            return api.run(str(self.inp), str(self.out), cache_dir=str(Path(self.tmp.name) / "c"),
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
        n, logs = [], []

        def send(*a, **k):
            n.append(1)
            return fake(429, {"error": {"code": "subscription_sharing_usage_limit_exceeded", "message": "m"}},
                        {"X-Oai-Request-Id": "req_1", "x-codex-primary-used-percent": "100"})

        with mock.patch.object(net, "send", send):
            code = api.run(str(self.inp), str(self.out), model="m", cache_dir=str(Path(self.tmp.name) / "c"),
                           max_requests=None, min_interval_s=0, log=logs.append)
        self.assertEqual(code, 3)
        self.assertEqual(len(n), 1)
        self.assertEqual(self.out.read_text(), "")
        self.assertIn("req_1", logs[-1])
        self.assertIn("x-codex-primary-used-percent", logs[-1])
        self.assertIn("chatgpt.com/settings/usage", logs[-1])

    def test_stop_statuses_and_codes(self):
        for resp in (fake(403, {"error": {"code": "subscription_sharing_user_not_eligible"}}),
                     fake(403, {"error": {"code": "chatpass_v2_scope_not_authorized"}}),
                     fake(503, {"detail": "direct routing unavailable"}),
                     fake(403, {"detail": "region"})):
            self.out.unlink(missing_ok=True)
            self.assertEqual(self.run_cli(lambda *a, r=resp, **k: r), 3)

    def test_limit_as_response_failed_stops(self):
        def send(*a, **k):
            return sse({"type": "response.failed", "response": {"error": {
                "code": "subscription_sharing_usage_limit_exceeded"}}})

        self.assertEqual(self.run_cli(send), 3)

    def test_network_error_stops_cleanly(self):
        def send(*a, **k):
            raise urllib.error.URLError("down")

        self.assertEqual(self.run_cli(send), 3)

    def test_401_refreshes_once(self):
        seq = []

        def send(method, url, headers=None, body=None, timeout=0):
            if url == auth.TOKEN_URL:
                seq.append("refresh")
                return fake(200, {"access_token": "new", "refresh_token": "r2", "expires_in": 3600})
            seq.append(headers["Authorization"])
            return fake(401, b"{}") if headers["Authorization"] == "Bearer tok" else sse(*completed())

        self.assertEqual(self.run_cli(send), 0)
        self.assertEqual(seq[:3], ["Bearer tok", "refresh", "Bearer new"])
        self.assertEqual(seq.count("refresh"), 1)

    def test_401_after_refresh_stops(self):
        def send(method, url, headers=None, body=None, timeout=0):
            if url == auth.TOKEN_URL:
                return fake(200, {"access_token": "new", "refresh_token": "r2", "expires_in": 3600})
            return fake(401, {"error": {"code": "subscription_sharing_invalid_user"}})

        self.assertEqual(self.run_cli(send), 3)

    def test_other_error_recorded_and_continues(self):
        def send(*a, **k):
            return fake(400, {"error": {"code": "subscription_sharing_unsupported_capability", "param": "x"}},
                        {"x-request-id": "req_2"})

        self.assertEqual(self.run_cli(send), 0)
        self.assertEqual(self.lines()[0]["error"]["param"], "x")
        self.assertEqual(self.lines()[0]["error"]["request_id"], "req_2")
        self.assertEqual(len(self.lines()), 2)

    def test_max_requests(self):
        self.assertEqual(self.run_cli(lambda *a, **k: sse(*completed()), max_requests=1), 3)
        self.assertEqual(len(self.lines()), 1)

    def test_model_required_and_input_validated(self):
        with self.assertRaises(api.StopRun):
            self.run_cli(lambda *a, **k: sse(*completed()), model=None)
        self.inp.write_text('{"id": 1}\n', encoding="utf-8")
        with self.assertRaises(api.StopRun):
            self.run_cli(lambda *a, **k: sse(*completed()))

    def test_plan_scope_required(self):
        store.save(dict(store.load(), scopes=["openid"]))
        with self.assertRaises(api.StopRun):
            self.run_cli(lambda *a, **k: sse(*completed()))

class ReasoningTextAndStdin(Run):
    FMT = {"format": {"type": "json_schema", "name": "x", "schema": {"type": "object"}, "strict": True}}

    def test_body_passes_reasoning_and_text_never_unsupported(self):
        b = api.build_body("m", "i", "q", {"effort": "low"}, self.FMT)
        self.assertEqual(b["reasoning"], {"effort": "low"})
        self.assertEqual(b["text"], self.FMT)
        self.assertFalse(set(b) & set(api.UNSUPPORTED_FIELDS))
        self.assertNotIn("reasoning", api.build_body("m", "i", "q"))
        self.assertNotIn("text", api.build_body("m", "i", "q"))

    def test_cache_key_unchanged_without_and_distinct_with(self):
        self.assertEqual(api.request_key("m", "i", "q"), api.request_key("m", "i", "q", None, None))
        self.assertNotEqual(api.request_key("m", "i", "q"), api.request_key("m", "i", "q", {"effort": "low"}))
        self.assertNotEqual(api.request_key("m", "i", "q", {"effort": "low"}),
                            api.request_key("m", "i", "q", {"effort": "high"}))
        self.assertNotEqual(api.request_key("m", "i", "q", None, self.FMT), api.request_key("m", "i", "q"))

    def test_run_sends_optional_fields_and_validates(self):
        self.inp.write_text(json.dumps({"id": "a", "input": "q", "reasoning": {"effort": "low"},
                                        "text": self.FMT}) + "\n", encoding="utf-8")
        bodies = []

        def send(method, url, headers=None, body=None, timeout=0):
            bodies.append(json.loads(body))
            return sse(*completed("{}"))

        self.assertEqual(self.run_cli(send), 0)
        self.assertEqual(bodies[0]["reasoning"], {"effort": "low"})
        self.assertEqual(bodies[0]["text"], self.FMT)
        self.assertFalse(set(bodies[0]) & set(api.UNSUPPORTED_FIELDS))
        self.inp.write_text(json.dumps({"id": "a", "input": "q", "reasoning": "low"}) + "\n", encoding="utf-8")
        with self.assertRaises(api.StopRun):
            self.run_cli(send)

    def stdin(self, raw, send, **kw):
        out = io.StringIO()
        with mock.patch.object(net, "send", send):
            code = api.run_stdin(raw, out, model="m", cache_dir=str(Path(self.tmp.name) / "c"),
                                 log=lambda *_: None, **kw)
        return code, out.getvalue()

    def test_stdin_single_request_one_line_and_cached(self):
        n = []

        def send(*a, **k):
            n.append(1)
            return sse(*completed("ok"))

        raw = json.dumps({"input": "q", "instructions": "I", "reasoning": {"effort": "low"}})
        code, out = self.stdin(raw, send)
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["output_text"], "ok")
        self.assertEqual(json.loads(lines[0])["id"], "stdin")
        code, out = self.stdin(raw, send)
        self.assertEqual(len(n), 1)  # second call came from the cache

    def test_stdin_limit_exit_and_bad_input(self):
        def send(*a, **k):
            return fake(429, {"error": {"code": "subscription_sharing_usage_limit_exceeded"}})

        code, out = self.stdin(json.dumps({"input": "q"}), send)
        self.assertEqual(code, 3)
        self.assertEqual(out, "")
        with self.assertRaises(api.StopRun):
            self.stdin("not json", send)
        with self.assertRaises(api.StopRun):
            self.stdin(json.dumps({"instructions": "x"}), send)

    def _stdin_run(self, payload: dict, reply: str, cache: str):
        """Runs --stdin-json with byte-backed pipes, as a real subprocess pipe is; returns (code, stdout text, bodies)."""
        from siwc_judge import cli
        sent = []

        def fake_send(*a, **k):
            sent.append(a[3] if len(a) > 3 else k.get("body"))
            return sse(*completed(reply))

        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload, ensure_ascii=False).encode("utf-8")), encoding="cp1252")
        stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        with mock.patch.object(net, "send", fake_send), mock.patch("sys.stdin", stdin), \
                mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", io.StringIO()):
            code = cli.main(["run", "--stdin-json", "--model", "m", "--cache", str(Path(self.tmp.name) / cache)])
            stdout.flush()
            text = stdout.buffer.getvalue().decode("utf-8")
        return code, text, sent

    def test_cli_stdin_mode(self):
        from siwc_judge import cli
        code, text, _ = self._stdin_run({"input": "q"}, "hi", "c2")
        self.assertEqual(code, 0)
        self.assertEqual(len(text.splitlines()), 1)
        with self.assertRaises(SystemExit):
            cli.main(["run", "--model", "m"])

    def test_cli_stdin_mode_is_utf8_whatever_the_console_code_page(self):
        # A cp1252 console must not turn UTF-8 pipe bytes into lone surrogates (they cannot be sent).
        code, text, sent = self._stdin_run({"input": "naïve café — 東京"}, "naïve", "c3")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)["output_text"], "naïve")
        body = sent[0]
        body = body.decode("utf-8") if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body, ensure_ascii=False))
        self.assertIn("東京", json.dumps(json.loads(body), ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
