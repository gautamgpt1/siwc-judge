# siwc-judge

A tiny, dependency-free (Python 3.10+ standard library) CLI that sends batches of
[Responses API](https://developers.openai.com/api/docs/api-reference/responses) requests using
your own ChatGPT plan through OpenAI's "Sign in with ChatGPT" (SIWC) token sharing.
It is a generic batch runner: you supply the prompts.

Follows OpenAI's docs:
[token sharing (open source)](https://developers.openai.com/siwc/token-sharing-open-source),
[sign in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in),
[accounts and sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions),
[models and inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference),
[token reference](https://developers.openai.com/siwc/token-sharing-open-source/token-reference),
[errors and recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery),
[preview limitations](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations).

## Install

```
pip install .        # or run in place: python -m siwc_judge ...
```

## Usage

```
python -m siwc_judge login      # browser sign-in; first time registers a client (agent name: siwc-judge)
python -m siwc_judge models     # catalog (not an entitlement check)
python -m siwc_judge run --in requests.jsonl --out responses.jsonl [--model M] [--cache DIR] \
                         [--max-requests N] [--min-interval-s 1]
python -m siwc_judge refresh
python -m siwc_judge logout     # revokes the refresh token, deletes local credentials
```

Input lines: `{"id": "...", "instructions": "...", "input": "text" | [responses input items]}`.
Output lines: `{"id", "model", "output_text", "usage", "error"}`.
Without `--model`, the first model the catalog lists is used.

Credentials live outside any repo in `~/.siwc-judge/credentials.json` (override with
`SIWC_JUDGE_HOME`), written with owner-only permissions where the OS supports it. Tokens are never printed.
Results are cached by sha256 of (model, instructions, input) so reruns skip unchanged requests.
Requests run sequentially. On a usage or rate limit the run stops cleanly (exit code 3) and never retries in a loop.

## Documented restrictions

- Requests always use `stream: true`, `store: false`; `temperature`, `top_p`, `max_output_tokens` and the other
  unsupported fields are never sent.
- Usage counts against your ChatGPT plan; for Plus, the five-hour limit is shared with every other app.
  Review it at <https://chatgpt.com/settings/usage>.
- Preview feature; behaviour may change.

## Terms

Intended for personal use of your own account, within OpenAI's terms. Not affiliated with OpenAI.

## Tests

```
python -m unittest
```

MIT licensed.
