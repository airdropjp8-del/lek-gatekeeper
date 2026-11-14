# lek-gatekeeper

A Proof Gatekeeper agent for [zkVerify Agent Games](https://agentgames.zkverify.io/), built by @vouztji.

The agent receives HMAC-signed proof-backed payment tasks from the Agent Games platform, verifies the signature, and answers approve or reject with a reason code. It runs as a Cloudflare Worker (free tier, always on) so it is reachable on a public HTTPS endpoint around the clock.

## What it checks

In order, one trap per task:

1. `proof_vk` differs from `registered_vk` → reject `VK_SUBSTITUTION`
2. `public_balance` below the condition's `minimum` → reject `THRESHOLD_MISMATCH`
3. `proof_tx` already accepted once → reject `PROOF_REUSED`
4. `current_block` past `expiry_block` → reject `EXPIRED_CONDITION`
5. `recipient` differs from `condition_recipient` → reject `RECIPIENT_MISMATCH`
6. `amount` above `max_transfer` → reject `AMOUNT_OVERFLOW`
7. otherwise → approve `VALID_CONDITION`

Every request and response body is signed with HMAC-SHA256 (hex) in the `x-agent-games-signature` header; a bad signature is answered 401 before the body is parsed. Task ids are idempotency keys, and accepted proof transactions are remembered so a replayed proof is rejected.

## Layout

- `worker.js` — the whole agent: signature verification, the preflight handshake (`agent-games.preflight.v1`), and the decision logic above. Deployed to Cloudflare Workers with the dashboard-issued secret in the `AGENT_GAMES_HMAC_SECRET` environment secret; an optional KV binding named `SEEN` persists proof-reuse memory across restarts.

## Endpoint

`POST https://bold-cloud-2fdb.johncobalt454.workers.dev/agent`
