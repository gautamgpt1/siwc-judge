"""Sign in with ChatGPT: authorization-code + PKCE, refresh, revoke.

Follows https://developers.openai.com/siwc/token-sharing-open-source
"""
from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone

from . import jwtlib, net, store

ISSUER = "https://auth.openai.com"
AUTHORIZE_URL = ISSUER + "/api/accounts/authorize"
TOKEN_URL = ISSUER + "/api/accounts/oauth/token"
DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration"
JWKS_URL = ISSUER + "/.well-known/jwks.json"
RESOURCE = "https://api.openai.com/v1"
DYNAMIC_CLIENT = "dynamic_agent_client"
AGENT_NAME = "siwc-judge"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
PLAN_SCOPE = "chatgpt.tokens.use.direct"
DEFAULT_PORT = 1455
CALLBACK_PATH = "/auth/callback"
REFRESH_SKEW = 120
LOGIN_CMD = "python -m siwc_judge login"


class AuthError(Exception):
    pass


def _clean(value) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "?", str(value))[:100]  # callback/server text shown in a terminal


def new_pkce() -> tuple[str, str]:
    verifier = jwtlib.b64url_encode(secrets.token_bytes(48))
    challenge = jwtlib.b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_authorize_url(*, client_id: str, host_id: str, redirect_uri: str, state: str, nonce: str,
                        challenge: str, reauth: dict | None = None, consent: bool = False) -> str:
    q = {
        "client_id": client_id,
        "ext_agent_host_id": host_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "resource": RESOURCE,
        "state": state,
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
    }
    if reauth:  # returning sign-in: no agent_name_hint, send retained hints
        if reauth.get("id_token"):
            q["id_token_hint"] = reauth["id_token"]
        if reauth.get("email"):
            q["login_hint"] = reauth["email"]
    else:
        q["agent_name_hint"] = AGENT_NAME
    if consent:  # re-ask for plan usage after a decline; force_reconsent=true needs OpenAI's go-ahead first
        q["prompt"] = "consent"
    return AUTHORIZE_URL + "?" + urllib.parse.urlencode(q, quote_via=urllib.parse.quote)


def _token_request(fields: dict) -> tuple[int, dict]:
    body, headers = net.form(fields)
    r = net.send("POST", TOKEN_URL, headers, body, timeout=60)
    try:
        data = json.loads(r.read().decode("utf-8", "replace"))
    except ValueError:
        data = {}
    return r.status, data if isinstance(data, dict) else {}


def _error_code(data: dict) -> str | None:
    code = data.get("error")
    if isinstance(code, dict):
        code = code.get("code")
    return _clean(code) if code else None


def exchange_code(*, client_id: str, code: str, verifier: str, redirect_uri: str) -> dict:
    status, data = _token_request({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "resource": RESOURCE,
    })
    if status != 200:
        raise AuthError(f"code exchange failed: HTTP {status} {_error_code(data) or 'unknown_error'}; "
                        f"run login again ({LOGIN_CMD})")
    return data


def parse_token_response(tok: dict, now: float | None = None) -> dict:
    """Normalise a token response (never includes secrets in errors). Omitted scope = unchanged (RFC 6749 5.1)."""
    for k in ("access_token", "refresh_token"):
        if not tok.get(k):
            raise AuthError(f"token response missing {k}")
    now = time.time() if now is None else now
    try:
        lifetime = float(tok.get("expires_in") or 3600)
    except (TypeError, ValueError):
        lifetime = 3600.0
    earliest = tok.get("earliest_refresh_at")
    return {
        "access_token": tok["access_token"],
        "refresh_token": tok["refresh_token"],
        "id_token": tok.get("id_token"),
        "token_type": tok.get("token_type", "Bearer"),
        "expires_in": tok.get("expires_in", 3600),
        "expires_at": now + lifetime,
        "earliest_refresh_at": earliest if isinstance(earliest, (int, float)) and not isinstance(earliest, bool)
        else None,
        "scopes": sorted(tok["scope"].split()) if isinstance(tok.get("scope"), str) else None,
    }


def fetch_jwks() -> dict:
    r = net.send("GET", JWKS_URL, {"Accept": "application/json"}, timeout=30)
    if r.status != 200:
        raise AuthError(f"JWKS fetch failed: HTTP {r.status}")
    return r.json()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def finish_login(*, client_id: str, host_id: str, code: str, verifier: str, redirect_uri: str,
                 nonce: str, previous: dict | None) -> dict:
    tokens = parse_token_response(exchange_code(client_id=client_id, code=code, verifier=verifier,
                                                redirect_uri=redirect_uri))
    if not tokens["id_token"]:
        raise AuthError("token response has no id_token")
    try:
        claims = jwtlib.validate_id_token(tokens["id_token"], fetch_jwks(), issuer=ISSUER,
                                          audience=client_id, nonce=nonce, now=time.time())
    except jwtlib.JwtError as e:
        raise AuthError(f"ID token rejected: {e}") from None
    if previous and previous.get("subject") and previous["subject"] != claims["sub"]:
        raise AuthError("signed-in account differs from the saved account; credentials not replaced "
                        "(to switch accounts: logout --forget, then login)")
    if tokens["scopes"] is None:
        tokens["scopes"] = sorted(SCOPES.split())
    record = {
        "email": claims.get("email") or (previous or {}).get("email"),
        "issuer": ISSUER,
        "subject": claims["sub"],
        "client_id": client_id,
        "ext_agent_host_id": host_id,
        **{k: v for k, v in tokens.items() if v is not None},
        "saved_at": _now_iso(),
    }
    record["plan_usage_enabled"] = PLAN_SCOPE in record["scopes"]
    with store.lock():
        store.save(record)
    if not record["plan_usage_enabled"]:
        raise AuthError("sign-in succeeded but ChatGPT plan usage (chatgpt.tokens.use.direct) was not granted; "
                        f"to enable it run: {LOGIN_CMD} --consent")
    return record


class _Server(http.server.HTTPServer):
    # On Windows SO_REUSEADDR lets a second socket bind a port that is already listening (for example another
    # tool's login server on 1455), so the callback could reach either. Bind exclusively and fall back instead.
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class _Handler(http.server.BaseHTTPRequestHandler):
    timeout = 10  # a stalled local connection cannot block the single-threaded listener

    def _reply(self, status: int, text: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path != CALLBACK_PATH:
            return self._reply(404, "Not found.")
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        srv = self.server
        if srv.result is not None or not hmac.compare_digest(q.get("state", "").encode(), srv.state.encode()):
            return self._reply(400, "Invalid or stale sign-in response.")  # keep waiting for the real callback
        srv.result = q  # first matching callback wins; the listener then closes
        self._reply(200, "Sign-in failed; see the terminal." if q.get("error")
                    else "Sign-in received. You can close this tab and return to the terminal.")
        threading.Thread(target=srv.shutdown, daemon=True).start()

    def log_message(self, *a):  # keep codes out of logs
        pass


def _listen(state: str) -> _Server:
    for port in (DEFAULT_PORT, 0):  # the docs allow any loopback port; only the port may vary
        try:
            srv = _Server(("127.0.0.1", port), _Handler)
        except OSError:
            continue
        srv.result, srv.state = None, state
        return srv
    raise AuthError("could not open a loopback port")


def login(open_browser=webbrowser.open, timeout: float = 300, consent: bool = False) -> dict:
    host = store.host_id()
    previous = store.load()
    reauth = previous if previous and previous.get("client_id") else None
    consent = consent or bool(reauth and reauth.get("plan_usage_enabled") is False)
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = new_pkce()
    srv = _listen(state)
    redirect_uri = f"http://127.0.0.1:{srv.server_address[1]}{CALLBACK_PATH}"
    client_id = reauth["client_id"] if reauth else DYNAMIC_CLIENT
    url = build_authorize_url(client_id=client_id, host_id=host, redirect_uri=redirect_uri, state=state,
                              nonce=nonce, challenge=challenge, reauth=reauth, consent=consent)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        print("Opening the browser to sign in with ChatGPT. If it does not open, visit the URL printed below.")
        print("[URL withheld: it contains an ID-token hint]" if "id_token_hint=" in url else url)
        open_browser(url)
        t.join(timeout)
    finally:
        if t.is_alive():
            srv.shutdown()
        srv.server_close()
    res = srv.result  # state already matched (constant-time) by the listener
    if not res:
        raise AuthError("timed out waiting for the sign-in callback")
    if res.get("error"):
        hint = f"; to allow plan usage later run: {LOGIN_CMD} --consent" if res["error"] == "access_denied" else ""
        raise AuthError(f"authorization failed: {_clean(res['error'])}{hint}")
    code = res.get("code")
    if not code:
        raise AuthError("callback had no code")
    if reauth:
        if res.get("client_id") and res["client_id"] != reauth["client_id"]:
            raise AuthError("callback client_id differs from the saved client_id")
        issued = reauth["client_id"]
    else:
        issued = res.get("client_id")
        if not issued or issued == DYNAMIC_CLIENT:
            raise AuthError("registration incomplete: callback did not include an issued client_id")
        with store.lock():  # keep the new registration even if the exchange below fails
            store.save({"issuer": ISSUER, "client_id": issued, "ext_agent_host_id": host})
    return finish_login(client_id=issued, host_id=host, code=code, verifier=verifier,
                        redirect_uri=redirect_uri, nonce=nonce, previous=reauth)


UNUSABLE_REFRESH = {"invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired",
                    "refresh_token_invalidated", "refresh_token_reused"}


def refresh(record: dict | None = None, *, rejected: str | None = None) -> dict:
    """Refresh under a cross-process lock, adopting tokens another process already rotated."""
    with store.lock():
        current = store.load() or record
        if not current or not current.get("refresh_token"):
            raise AuthError(f"not signed in; run: {LOGIN_CMD}")
        stale = rejected or (record or {}).get("access_token")
        if (stale and current.get("access_token") not in (None, stale)
                and current.get("expires_at", 0) - REFRESH_SKEW > time.time()):
            return current
        status, data = _token_request({
            "grant_type": "refresh_token",
            "client_id": current["client_id"],
            "refresh_token": current["refresh_token"],
            "resource": RESOURCE,
        })
        if status != 200:
            code = _error_code(data)
            if code in UNUSABLE_REFRESH:
                store.save(store.clear_tokens(current, keep_id_token=True))
                raise AuthError(f"refresh token unusable ({code}); run: {LOGIN_CMD}")
            if code == "invalid_client":
                raise AuthError("refresh rejected: invalid_client (client registration problem); credentials kept")
            raise AuthError(f"refresh failed: HTTP {status} {code or ''}".strip() + "; credentials kept")
        tokens = parse_token_response(data)
        new = dict(current)
        new.pop("earliest_refresh_at", None)
        new.update({k: v for k, v in tokens.items() if v is not None})
        new["plan_usage_enabled"] = PLAN_SCOPE in (new.get("scopes") or [])
        new["saved_at"] = _now_iso()
        store.save(new)  # access token, expiry, scopes and rotated refresh token replaced together
        return new


def ensure_fresh(record: dict, skew: float = REFRESH_SKEW) -> dict:
    now, exp = time.time(), record.get("expires_at", 0)
    if exp - skew > now:
        return record
    earliest = record.get("earliest_refresh_at")
    if isinstance(earliest, (int, float)) and now < earliest and now < exp:
        return record  # honour earliest_refresh_at while the current token still works
    return refresh(record)


def _revoke(record: dict) -> bool:
    body, headers = net.form({"token": record["refresh_token"], "token_type_hint": "refresh_token",
                              "client_id": record["client_id"]})
    endpoint = None
    for attempt in range(3):
        try:
            if endpoint is None:
                d = net.send("GET", DISCOVERY_URL, {"Accept": "application/json"}, timeout=30)
                if d.status != 200:
                    d.read()
                    raise OSError(f"discovery HTTP {d.status}")
                endpoint = d.json().get("revocation_endpoint")
                if not isinstance(endpoint, str) or not endpoint.startswith(ISSUER + "/"):
                    return False  # never send the refresh token anywhere but OpenAI's auth server
            r = net.send("POST", endpoint, headers, body, timeout=30)
            r.read()
            if r.status == 200:
                return True
            if r.status < 500:
                return False
        except (OSError, ValueError, AttributeError):
            pass  # network failure or 5xx: retry with backoff
        if attempt < 2:
            time.sleep(2 ** attempt)
    return False


def logout(forget: bool = False) -> str:
    with store.lock():
        record = store.load()
        if not record:
            return "no saved credentials"
        msg = "nothing to revoke"
        if record.get("refresh_token"):
            msg = ("remote revocation confirmed" if _revoke(record)
                   else "remote revocation was NOT confirmed; disconnect the app in ChatGPT Settings")
        if forget:
            store.delete()
            return "signed out and registration forgotten; " + msg
        store.save(store.clear_tokens(record, keep_id_token=False))  # keep client_id + identity for re-login
    return "signed out locally; " + msg
