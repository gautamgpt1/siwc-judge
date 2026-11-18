# siwc-judge

A tiny, dependency-free (Python 3.10+ standard library) CLI that sends batches of
[Responses API](https://developers.openai.com/api/docs/api-reference/responses) requests using
your own ChatGPT plan through OpenAI's "Sign in with ChatGPT" (SIWC) token sharing.
It is a batch runner for your own prompts, for example LLM-as-judge evaluations; you supply the prompts.

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
python -m siwc_judge login [--consent]   # browser sign-in; the first one registers a client (agent name: siwc-judge)
python -m siwc_judge models              # catalog (not an entitlement check)
python -m siwc_judge run --in requests.jsonl --out responses.jsonl --model SLUG [--cache DIR] \
                         [--max-requests N] [--min-interval-s 1]
python -m siwc_judge refresh
python -m siwc_judge logout [--forget]   # revokes the refresh token and clears local tokens
```

Input lines: `{"id": "...", "instructions": "...", "input": "text" | [responses input items]}`
(`instructions` is optional). Output lines: `{"id", "model", "output_text", "usage", "error"}`.
`--model` is required: pick a slug from `models`, so a run never changes model silently.

Sign-in listens on `http://127.0.0.1:1455/auth/callback`, or on a free loopback port when 1455 is busy.
Later sign-ins reuse the issued client ID and this machine's host ID. `login --consent` asks for plan-usage
permission again (it is added automatically if you declined it before). `logout` keeps the registration so the
next sign-in needs no new client; `logout --forget` also drops it, which you need before switching accounts.

Credentials live outside any repo in `~/.siwc-judge/credentials.json` (override with
`SIWC_JUDGE_HOME`), written atomically with owner-only permissions where the OS supports it. Tokens are never
printed, and refreshes are serialized across processes. Results are cached by sha256 of (model, instructions,
input), so reruns skip unchanged requests. Requests run sequentially. On a usage limit, eligibility or
permission error, temporary unavailability, or a network failure, the run stops cleanly (exit code 3) and never
retries in a loop. The message includes the request ID and any usage headers.

## Documented restrictions

- Requests always use `stream: true`, `store: false`; `temperature`, `top_p`, `max_output_tokens` and the other
  unsupported fields are never sent.
- Usage counts against your ChatGPT plan. For Plus, the five-hour limit is shared with every other app.
  Review it at <https://chatgpt.com/settings/usage>.
- Preview feature; behaviour may change.

## Terms

Intended for personal use of your own account, within OpenAI's
[Sign in with ChatGPT terms](https://openai.com/policies/sign-in-with-chatgpt-terms/). Do not wrap it as an API
for other apps or people. Not affiliated with OpenAI.

## Tests

```
python -m unittest
```

MIT licensed.
