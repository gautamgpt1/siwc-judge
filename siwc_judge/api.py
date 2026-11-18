"""Models listing and streaming Responses API calls on the ChatGPT plan."""
from __future__ import annotations

import hashlib
import http.client
import json
import time
from pathlib import Path

from . import auth, net, store

BASE = "https://api.openai.com/v1"
USAGE_URL = "https://chatgpt.com/settings/usage"

# Request fields the ChatGPT-plan route rejects (preview limitations); never sent.
UNSUPPORTED_FIELDS = (
    "background", "conversation", "max_output_tokens", "max_tool_calls", "metadata", "moderation",
    "multi_agent", "prompt", "prompt_cache_retention", "safety_identifier", "temperature",
    "top_logprobs", "top_p", "truncation", "user", "previous_response_id",
)

# Codes after which no further request should be sent (errors-and-recovery): limits, eligibility, routing,
# identity and temporary unavailability. `chatpass_v2_*` codes are matched by prefix.
STOP_CODES = {
    "subscription_sharing_usage_limit_exceeded",  # 429 pause; review usage settings
    "subscription_sharing_usage_unavailable",  # 503 retry later
    "subscription_sharing_user_unavailable",  # 503 retry later
    "subscription_sharing_user_not_eligible",  # 403 do not repeat
    "subscription_sharing_route_not_supported",  # 403 configuration
    "subscription_sharing_invalid_user",  # 401 sign in again after a terminal refresh error
    "rate_limit_exceeded",
}
STOP_STATUSES = {401, 403, 429, 503}  # direct-admission statuses without a structured code stop too


class StopRun(Exception):
    """A condition under which no further request should be attempted."""


class Unauthorized(Exception):
    pass


def build_body(model: str, instructions: str | None, inp) -> dict:
    if isinstance(inp, str):
        inp = [{"role": "user", "content": inp}]
    body = {"model": model, "input": inp, "store": False, "stream": True}
    if instructions is not None:
        body["instructions"] = instructions
    return body


def request_key(model: str, instructions: str | None, inp) -> str:
    blob = json.dumps([model, instructions, inp], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _auth_headers(token: str, extra: dict | None = None) -> dict:
    h = {"Authorization": f"Bearer {token}"}
    h.update(extra or {})
    return h


def list_models(record: dict) -> list[dict]:
    r = net.send("GET", BASE + "/models", _auth_headers(record["access_token"], {"Accept": "application/json"}),
                 timeout=60)
    if r.status != 200:
        raise StopRun(_stop_message(_error_from_http(r), "models request failed"))
    return r.json().get("models", [])


def parse_sse(lines) -> dict:
    """Consume SSE lines; return {'output_text','usage','model','error'}. Success only via response.completed."""
    deltas: list[str] = []
    done: list[str] = []
    final: list[str] = []
    out = {"output_text": "", "usage": None, "model": None, "error": None}
    completed = False
    data_buf: list[str] = []

    def handle(payload: str):
        nonlocal completed
        if payload.strip() == "[DONE]":
            return
        try:
            ev = json.loads(payload)
        except ValueError:
            return
        t = ev.get("type")
        if t == "response.output_text.delta":
            deltas.append(ev.get("delta", ""))
        elif t == "response.output_text.done":
            done.append(ev.get("text", ""))
        elif t == "response.completed":
            completed = True
            resp = ev.get("response") or {}
            out["usage"] = resp.get("usage")
            out["model"] = resp.get("model")
            for item in resp.get("output") or []:  # often empty on this route; deltas carry the text
                for c in item.get("content") or []:
                    if c.get("type") == "output_text":
                        final.append(c.get("text", ""))
        elif t == "response.failed":
            err = (ev.get("response") or {}).get("error") or {}
            out["error"] = {"code": err.get("code") or "unknown_error", "message": err.get("message")}
        elif t == "response.incomplete":
            det = (ev.get("response") or {}).get("incomplete_details") or {}
            out["error"] = {"code": "incomplete", "message": det.get("reason")}
        elif t == "error":
            err = ev.get("error") if isinstance(ev.get("error"), dict) else ev
            out["error"] = {"code": err.get("code") or "error", "message": err.get("message")}

    for line in lines:
        if line == "":
            if data_buf:
                handle("\n".join(data_buf))
                data_buf = []
        elif line.startswith("data:"):
            data_buf.append(line[5:].lstrip())
    if data_buf:
        handle("\n".join(data_buf))
    out["output_text"] = "".join(deltas) or "".join(done) or "".join(final)
    if not completed and not out["error"]:
        out["error"] = {"code": "stream_incomplete", "message": "stream ended without response.completed"}
    return out


def _request_id(r: net.Response) -> str | None:
    return r.header("x-request-id") or r.header("x-oai-request-id") or r.header("openai-request-id")


def _limit_headers(r: net.Response) -> dict:
    return {k.lower(): v for k, v in r.headers.items()
            if k.lower().startswith(("x-codex-", "x-ratelimit-")) or k.lower() in ("retry-after", "retry-after-ms")}


def _error_from_http(r: net.Response) -> dict:
    raw = r.read().decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except ValueError:
        data = {}
    err = data.get("error") if isinstance(data, dict) else None
    if isinstance(err, dict):
        e = {"code": err.get("code"), "message": err.get("message"), "param": err.get("param")}
    else:  # direct admission can answer {"detail": "..."}: diagnostic text, not a code
        e = {"code": None, "message": (data.get("detail") if isinstance(data, dict) else None) or raw[:300]}
    e["status"] = r.status
    rid = _request_id(r)
    if rid:
        e["request_id"] = rid
    limits = _limit_headers(r)
    if limits:
        e["limits"] = limits
    return e


def _is_stop(err: dict) -> bool:
    code = err.get("code") or ""
    return code in STOP_CODES or code.startswith("chatpass_v2_") or err.get("status") in STOP_STATUSES


def _stop_message(err: dict, what: str = "stopping") -> str:
    msg = f"{what}: {err.get('code') or 'error'} (HTTP {err.get('status', '?')})"
    if err.get("request_id"):
        msg += f", request id {err['request_id']}"
    if err.get("code") == "subscription_sharing_usage_limit_exceeded" or err.get("status") == 429:
        msg += f". A ChatGPT plan or app usage limit may be reached; review {USAGE_URL}"
    elif err.get("message"):
        msg += f". {str(err['message'])[:200]}"
    if err.get("limits"):
        msg += f". Limit headers: {json.dumps(err['limits'])}"
    return msg + ". Cached results are kept."


def call_once(token: str, body: dict) -> dict:
    """One streaming call. Returns the parsed result; raises Unauthorized on 401, StopRun on stop conditions."""
    try:
        r = net.send("POST", BASE + "/responses",
                     _auth_headers(token, {"Content-Type": "application/json", "Accept": "text/event-stream"}),
                     json.dumps(body).encode("utf-8"), timeout=600)
    except OSError as e:
        raise StopRun(f"stopping: network error before the response ({type(e).__name__}). "
                      "Cached results are kept.") from None
    if r.status == 401:
        raise Unauthorized(_error_from_http(r))
    if r.status != 200:
        err = _error_from_http(r)
        if _is_stop(err):
            raise StopRun(_stop_message(err))
        return {"output_text": "", "usage": None, "model": body["model"], "error": err}
    try:
        res = parse_sse(r.iter_lines())
    except (OSError, http.client.HTTPException) as e:
        raise StopRun(f"stopping: stream interrupted ({type(e).__name__}); that request may still count against "
                      "your plan. Cached results are kept.") from None
    finally:
        r.close()
    e = res["error"]
    if e:
        rid = _request_id(r)
        if rid:
            e["request_id"] = rid
        if _is_stop(e):
            raise StopRun(_stop_message(e))
    return res


def load_items(in_path: str) -> list[dict]:
    items = []
    for n, line in enumerate(Path(in_path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            it = json.loads(line)
        except ValueError:
            raise StopRun(f"{in_path}:{n}: not valid JSON") from None
        if (not isinstance(it, dict) or "id" not in it or not isinstance(it.get("input"), (str, list))
                or not isinstance(it.get("instructions", ""), str)):
            raise StopRun(f'{in_path}:{n}: needs "id", "input" (string or list) and optional string "instructions"')
        items.append(it)
    return items


def run(in_path: str, out_path: str, *, model: str | None, cache_dir: str | None, max_requests: int | None,
        min_interval_s: float, sleep=time.sleep, log=print) -> int:
    if not model:
        raise StopRun("pass --model (list choices with: python -m siwc_judge models)")
    items = load_items(in_path)
    record = auth.ensure_fresh(_need_creds())
    cache = Path(cache_dir) if cache_dir else store.home() / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    sent = hits = 0
    last = 0.0
    stopped: str | None = None
    with open(out_path, "w", encoding="utf-8") as out:
        for it in items:
            instructions = it.get("instructions")
            key = request_key(model, instructions, it["input"])
            cf = cache / f"{key}.json"
            if cf.exists():
                res = json.loads(cf.read_text(encoding="utf-8"))
                hits += 1
            else:
                if max_requests is not None and sent >= max_requests:
                    stopped = f"reached --max-requests {max_requests}"
                    break
                wait = min_interval_s - (time.monotonic() - last)
                if last and wait > 0:
                    sleep(wait)
                body = build_body(model, instructions, it["input"])
                try:
                    try:
                        res = call_once(record["access_token"], body)
                    except Unauthorized:
                        record = auth.refresh(record, rejected=record["access_token"])
                        res = call_once(record["access_token"], body)
                except Unauthorized as e:
                    err = e.args[0] if e.args else {"status": 401}
                    stopped = _stop_message(err) + f" Check the account and scopes, or run: {auth.LOGIN_CMD}"
                    break
                except (StopRun, auth.AuthError) as e:
                    stopped = str(e)
                    break
                except OSError as e:
                    stopped = f"stopping: network error during token refresh ({type(e).__name__})"
                    break
                last = time.monotonic()
                sent += 1
                if not res.get("error"):
                    tmp = cf.with_suffix(".tmp")
                    tmp.write_text(json.dumps(res), encoding="utf-8")
                    tmp.replace(cf)
            out.write(json.dumps({"id": it["id"], "model": res.get("model") or model,
                                  "output_text": res.get("output_text", ""), "usage": res.get("usage"),
                                  "error": res.get("error")}, ensure_ascii=False) + "\n")
            out.flush()
    log(f"done: {sent} sent, {hits} cached")
    if stopped:
        log(stopped)
        return 3
    return 0


def _need_creds() -> dict:
    rec = store.load()
    if not rec or not rec.get("access_token") or not rec.get("refresh_token"):
        raise StopRun(f"not signed in; run: {auth.LOGIN_CMD}")
    if auth.PLAN_SCOPE not in (rec.get("scopes") or []):
        raise StopRun(f"ChatGPT plan usage is not enabled for this sign-in; run: {auth.LOGIN_CMD} --consent")
    return rec
