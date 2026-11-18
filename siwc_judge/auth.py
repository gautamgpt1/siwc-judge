"""Sign in with ChatGPT: authorization-code + PKCE, refresh, revoke.

Follows https://developers.openai.com/siwc/token-sharing-open-source
"""
from __future__ import annotations

import hashlib
import http.server
import json
import secrets
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


class AuthError(Exception):
    pass


def new_pkce() -> tuple[str, str]:
    verifier = jwtlib.b64url_encode(secrets.token_bytes(48))
    challenge = jwtlib.b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_authorize_url(*, client_id: str, host_id: str, redirect_uri: str, state: str, nonce: str,
                        challenge: str, reauth: dict | None = None) -> str:
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
    return AUTHORIZE_URL + "?" + urllib.parse.urlencode(q, quote_via=urllib.parse.quote)


def _token_post(fields: dict) -> dict:
    body, headers = net.form(fields)
    r = net.send("POST", TOKEN_URL, headers, body, timeout=60)
    text = r.read().decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        data = {}
    if r.status != 200:
        code = data.get("error") if isinstance(data, dict) else None
        if isinstance(code, dict):
            code = code.get("code")
        raise AuthError(f"token endpoint HTTP {r.status}: {code or 'unknown_error'}")
    return data


def exchange_code(*, client_id: str, code: str, verifier: str, redirect_uri: str) -> dict:
    return _token_post({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "resource": RESOURCE,
    })


def parse_token_response(tok: dict, now: float | None = None) -> dict:
    """Normalise a token response (never includes secrets in errors)."""
    for k in ("access_token", "refresh_token"):
        if not tok.get(k):
            raise AuthError(f"token response missing {k}")
    now = time.time() if now is None else now
    scopes = sorted(tok.get("scope", "").split())
    return {
        "access_token": tok["access_token"],
        "refresh_token": tok["refresh_token"],
        "id_token": tok.get("id_token"),
        "token_type": tok.get("token_type", "Bearer"),
        "expires_in": tok.get("expires_in", 3600),
        "expires_at": now + float(tok.get("expires_in", 3600)),
        "scopes": scopes,
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
    claims = jwtlib.validate_id_token(tokens["id_token"], fetch_jwks(), issuer=ISSUER,
                                      audience=client_id, nonce=nonce, now=time.time())
    if previous and previous.get("subject") and previous["subject"] != claims["sub"]:
        raise AuthError("signed-in account differs from the saved account; refusing to replace credentials")
    record = {
        "email": claims.get("email"),
        "issuer": ISSUER,
        "subject": claims["sub"],
        "client_id": client_id,
        "ext_agent_host_id": host_id,
        **tokens,
        "saved_at": _now_iso(),
    }
    if PLAN_SCOPE not in tokens["scopes"]:
        record["plan_usage_enabled"] = False
        store.save(record)
        raise AuthError("sign-in succeeded but ChatGPT plan usage (chatgpt.tokens.use.direct) was not granted; "
                        "run login again and approve plan usage")
    record["plan_usage_enabled"] = True
    store.save(record)
    return record


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return
        self.server.result = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Sign-in complete. You can close this tab.")
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, *a):  # keep codes out of logs
        pass


def _listen() -> http.server.HTTPServer:
    for port in (DEFAULT_PORT, 0):
        try:
            srv = http.server.HTTPServer(("127.0.0.1", port), _Handler)
            srv.result = None
            return srv
        except OSError:
            continue
    raise AuthError("could not open a loopback port")


def login(open_browser=webbrowser.open, timeout: float = 300) -> dict:
    host = store.host_id()
    previous = store.load()
    reauth = previous if previous and previous.get("client_id") else None
    srv = _listen()
    redirect_uri = f"http://127.0.0.1:{srv.server_address[1]}{CALLBACK_PATH}"
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = new_pkce()
    client_id = reauth["client_id"] if reauth else DYNAMIC_CLIENT
    url = build_authorize_url(client_id=client_id, host_id=host, redirect_uri=redirect_uri, state=state,
                              nonce=nonce, challenge=challenge, reauth=reauth)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print("Opening the browser to sign in with ChatGPT. If it does not open, visit the URL printed below.")
    print("(The URL is not logged elsewhere.)")
    print(url if not reauth else "[reauthorization URL withheld because it contains an ID token hint]")
    open_browser(url)
    t.join(timeout)
    srv.server_close()
    res = srv.result
    if not res:
        raise AuthError("timed out waiting for the sign-in callback")
    if res.get("state") != state:
        raise AuthError("state mismatch")
    if res.get("error"):
        raise AuthError(f"authorization failed: {res['error']}")
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
    return finish_login(client_id=issued, host_id=host, code=code, verifier=verifier,
                        redirect_uri=redirect_uri, nonce=nonce, previous=reauth)


UNUSABLE_REFRESH = {"invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired",
                    "refresh_token_invalidated", "refresh_token_reused"}


def refresh(record: dict | None = None) -> dict:
    record = record or store.load()
    if not record:
        raise AuthError("not signed in; run: python -m siwc_judge login")
    body, headers = net.form({
        "grant_type": "refresh_token",
        "client_id": record["client_id"],
        "refresh_token": record["refresh_token"],
        "resource": RESOURCE,
    })
    r = net.send("POST", TOKEN_URL, headers, body, timeout=60)
    text = r.read().decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except ValueError:
        data = {}
    if r.status != 200:
        code = data.get("error") if isinstance(data, dict) else None
        if isinstance(code, dict):
            code = code.get("code")
        if code in UNUSABLE_REFRESH:
            raise AuthError(f"refresh token unusable ({code}); run: python -m siwc_judge login")
        raise AuthError(f"refresh failed: HTTP {r.status} {code or ''}".strip())
    tokens = parse_token_response(data)
    new = dict(record)
    new.update({k: v for k, v in tokens.items() if v is not None})
    new["saved_at"] = _now_iso()
    store.save(new)
    return new


def ensure_fresh(record: dict, skew: float = 120) -> dict:
    if record.get("expires_at", 0) - skew <= time.time():
        return refresh(record)
    return record


def logout() -> str:
    record = store.load()
    if not record:
        return "no saved credentials"
    msg = "remote revocation confirmed"
    try:
        d = net.send("GET", DISCOVERY_URL, {"Accept": "application/json"}, timeout=30)
        endpoint = d.json().get("revocation_endpoint") if d.status == 200 else None
        if not endpoint:
            raise AuthError("no revocation_endpoint")
        body, headers = net.form({"token": record["refresh_token"], "token_type_hint": "refresh_token",
                                  "client_id": record["client_id"]})
        ok = False
        for attempt in range(3):
            r = net.send("POST", endpoint, headers, body, timeout=30)
            r.read()
            if r.status == 200:
                ok = True
                break
            if r.status < 500:
                break
            time.sleep(2 ** attempt)
        if not ok:
            msg = "remote revocation was NOT confirmed; disconnect the app in ChatGPT Settings"
    except Exception:
        msg = "remote revocation was NOT confirmed; disconnect the app in ChatGPT Settings"
    store.delete()
    return "signed out locally; " + msg
