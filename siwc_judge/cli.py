from __future__ import annotations

import argparse
import json
import sys

from . import api, auth, store


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="siwc-judge", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("login", help="sign in with ChatGPT (opens the browser)")
    sub.add_parser("refresh", help="refresh the access token")
    sub.add_parser("logout", help="revoke the session and delete local credentials")
    sub.add_parser("models", help="list the model catalog (not an entitlement check)")
    r = sub.add_parser("run", help="run a JSONL file of requests")
    r.add_argument("--in", dest="inp", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--model")
    r.add_argument("--cache")
    r.add_argument("--max-requests", type=int)
    r.add_argument("--min-interval-s", type=float, default=1.0)
    a = p.parse_args(argv)
    try:
        if a.cmd == "login":
            rec = auth.login()
            print(f"signed in as {rec.get('email') or rec['subject']} (client {rec['client_id']}); "
                  f"credentials saved under {store.home()}")
        elif a.cmd == "refresh":
            auth.refresh()
            print("refreshed")
        elif a.cmd == "logout":
            print(auth.logout())
        elif a.cmd == "models":
            rec = auth.ensure_fresh(api._need_creds())
            for m in api.list_models(rec):
                print(json.dumps({"slug": m.get("slug"), "display_name": m.get("display_name"),
                                  "visibility": m.get("visibility")}))
        else:
            return api.run(a.inp, a.out, model=a.model, cache_dir=a.cache, max_requests=a.max_requests,
                           min_interval_s=a.min_interval_s)
    except (auth.AuthError, api.StopRun) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0
