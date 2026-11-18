"""Models listing and streaming Responses API calls on the ChatGPT plan."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import auth, net, store

BASE = "https://api.openai.com/v1"

# Request fields the ChatGPT-plan route rejects (preview limitations); never sent.
UNSUPPORTED_FIELDS = (
    "background", "conversation", "max_output_tokens", "max_tool_calls", "metadata", "moderation",
    "multi_agent", "prompt", "prompt_cache_retention", "safety_identifier", "temperature",
    "top_logprobs", "top_p", "truncation", "user", "previous_response_id",
)

STOP_CODES = {"subscription_sharing_usage_limit_exceeded", "subscription_sharing_usage_unavailable",
              "rate_limit_exceeded", "subscription_sharing_user_not_eligible"}


class StopRun(Exception):
    """A condition under which no further request should be attempted."""


class Unauthorized(Exception):
    pass


def build_body(model: str, instructions: str, inp) -> dict:
    if isinstance(inp, str):
        inp = [{"role": "user", "content": inp}]
    return {"model": model, "instructions": instructions, "input": inp, "store": False, "stream": True}


def request_key(model: str, instructions: str, inp) -> str:
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
        raise StopRun(f"models request failed: HTTP {r.status} {r.read()[:300].decode('utf-8', 'replace')}")
    return r.json().get("models", [])


def parse_sse(lines) -> dict:
    """Consume SSE lines; return {'output_text','usage','model','error'}. Success only via response.completed."""
    text_parts: list[str] = []
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
            text_parts.append(ev.get("delta", ""))
        elif t == "response.completed":
            completed = True
            resp = ev.get("response") or {}
            out["usage"] = resp.get("usage")
            out["model"] = resp.get("model")
            if not text_parts:
                for item in resp.get("output") or []:
                    for c in item.get("content") or []:
                        if c.get("type") == "output_text":
                            text_parts.append(c.get("text", ""))
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
    out["output_text"] = "".join(text_parts)
    if not completed and not out["error"]:
        out["error"] = {"code": "stream_incomplete", "message": "stream ended without response.completed"}
    return out


def _error_from_http(r: net.Response) -> dict:
    raw = r.read().decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except ValueError:
        data = {}
    err = data.get("error") if isinstance(data, dict) else None
    if isinstance(err, dict):
        e = {"code": err.get("code"), "message": err.get("message"), "param": err.get("param")}
    else:
        e = {"code": None, "message": (data.get("detail") if isinstance(data, dict) else None) or raw[:300]}
    e["status"] = r.status
    rid = r.headers.get("x-request-id") or r.headers.get("X-Request-Id")
    if rid:
        e["request_id"] = rid
    return e


def call_once(token: str, body: dict) -> dict:
    """One streaming call. Returns the parsed result; raises Unauthorized on 401, StopRun on limit errors."""
    r = net.send("POST", BASE + "/responses",
                 _auth_headers(token, {"Content-Type": "application/json", "Accept": "text/event-stream"}),
                 json.dumps(body).encode("utf-8"), timeout=600)
    if r.status == 401:
        r.read()
        raise Unauthorized()
    if r.status != 200:
        err = _error_from_http(r)
        if err.get("code") in STOP_CODES or err["status"] == 429:
            raise StopRun(_limit_message(err))
        return {"output_text": "", "usage": None, "model": body["model"], "error": err}
    try:
        res = parse_sse(r.iter_lines())
    finally:
        r.close()
    e = res["error"]
    if e and (e.get("code") in STOP_CODES):
        raise StopRun(_limit_message(e))
    return res


def _limit_message(err: dict) -> str:
    return (f"stopping: {err.get('code') or 'rate/usage limit'} (HTTP {err.get('status', '?')}). "
            "Your shared ChatGPT plan limit may be reached; review https://chatgpt.com/settings/usage "
            "and rerun later (cached results are kept).")


def run(in_path: str, out_path: str, *, model: str | None, cache_dir: str | None, max_requests: int | None,
        min_interval_s: float, sleep=time.sleep, log=print) -> int:
    record = auth.ensure_fresh(_need_creds())
    cache = Path(cache_dir) if cache_dir else store.home() / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    if not model:
        listed = [m for m in list_models(record) if m.get("visibility") == "list"]
        if not listed:
            raise StopRun("no model given and the catalog listed none; pass --model")
        model = listed[0]["slug"]
        log(f"using model {model} (first listed)")
    items = [json.loads(l) for l in Path(in_path).read_text(encoding="utf-8").splitlines() if l.strip()]
    sent = hits = 0
    last = 0.0
    stopped: str | None = None
    with open(out_path, "w", encoding="utf-8") as out:
        for it in items:
            key = request_key(model, it["instructions"], it["input"])
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
                body = build_body(model, it["instructions"], it["input"])
                try:
                    try:
                        res = call_once(record["access_token"], body)
                    except Unauthorized:
                        record = auth.refresh(record)
                        res = call_once(record["access_token"], body)
                except Unauthorized:
                    stopped = "HTTP 401 after a token refresh; run: python -m siwc_judge login"
                    break
                except StopRun as e:
                    stopped = str(e)
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
    if not rec:
        raise StopRun("not signed in; run: python -m siwc_judge login")
    if not rec.get("plan_usage_enabled", True):
        raise StopRun("ChatGPT plan usage is not enabled for this sign-in; run login again and approve it")
    return rec
