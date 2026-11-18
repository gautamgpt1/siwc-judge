"""siwc-judge: run Responses API requests on your own ChatGPT plan through Sign in with ChatGPT."""
from __future__ import annotations

import argparse
import json
import sys

from . import api, auth, store


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="siwc-judge", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login", help="sign in with ChatGPT (opens the browser)")
    lg.add_argument("--consent", action="store_true", help="ask again for permission to use the ChatGPT plan")
    sub.add_parser("refresh", help="refresh the access token")
    lo = sub.add_parser("logout", help="revoke the session and clear local tokens")
    lo.add_argument("--forget", action="store_true", help="also forget the client registration (to switch accounts)")
    sub.add_parser("models", help="list the model catalog (not an entitlement check)")
    r = sub.add_parser("run", help="run a JSONL file of requests")
    r.add_argument("--in", dest="inp")
    r.add_argument("--out")
    r.add_argument("--stdin-json", action="store_true",
                   help="single-request mode: one request object on stdin, one response line on stdout")
    r.add_argument("--model", required=True, help="model slug from the models command")
    r.add_argument("--cache")
    r.add_argument("--max-requests", type=int)
    r.add_argument("--min-interval-s", type=float, default=1.0)
    a = p.parse_args(argv)
    try:
        if a.cmd == "login":
            rec = auth.login(consent=a.consent)
            print(f"signed in as {rec.get('email') or rec['subject']} (client {rec['client_id']}); "
                  f"credentials saved under {store.home()}. Requests use your ChatGPT plan; manage usage at "
                  f"{api.USAGE_URL}")
        elif a.cmd == "refresh":
            auth.refresh()
            print("refreshed")
        elif a.cmd == "logout":
            print(auth.logout(forget=a.forget))
        elif a.cmd == "models":
            rec = auth.ensure_fresh(api._need_creds())
            for m in api.list_models(rec):
                print(json.dumps({"slug": m.get("slug"), "display_name": m.get("display_name"),
                                  "visibility": m.get("visibility")}))
        elif a.stdin_json:
            if a.inp or a.out:
                p.error("--stdin-json cannot be combined with --in/--out")
            # progress goes to stderr so stdout carries exactly one response line
            return api.run_stdin(sys.stdin.read(), sys.stdout, model=a.model, cache_dir=a.cache,
                                 log=lambda m: print(m, file=sys.stderr))
        else:
            if not (a.inp and a.out):
                p.error("run needs --in and --out (or --stdin-json)")
            return api.run(a.inp, a.out, model=a.model, cache_dir=a.cache, max_requests=a.max_requests,
                           min_interval_s=a.min_interval_s)
    except (auth.AuthError, api.StopRun) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except OSError as e:  # network or file problem; messages carry no tokens
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    return 0
