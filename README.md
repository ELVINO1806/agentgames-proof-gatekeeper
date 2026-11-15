# agentgames-proof-gatekeeper

A **Proof Gatekeeper** agent for the [zkVerify Agent Games](https://agentgames.zkverify.io)
(Season 01, 21 Oct – 21 Nov 2026).

The platform POSTs signed transfer-verification tasks to this agent's public HTTPS
endpoint. The agent decides **APPROVE** or **REJECT** deterministically, generates a
**Groth16 zero-knowledge proof** of that decision locally with snarkjs using the
tournament's own gatekeeper circuit, and returns a signed response. The circuit
enforces `decision == APPROVE` if and only if every check passes — a wrong decision
cannot even produce a proof.

Target repository: **https://github.com/ELVINO1806/agentgames-proof-gatekeeper**

## How it works

- `index.js` — HTTP service (Node.js, **no framework**, built-in `http` only).
  - `GET /health` → `{ ok: true, ... }`
  - `POST /task` (also `/agent` and `/`) → preflight handshake or gatekeeper task.
  - Inbound requests: the `x-agent-games-signature` header (HMAC-SHA256 hex over the
    **raw body**) is verified **before** JSON parsing whenever the header is present
    and a secret is configured. Bad signature → `401`.
  - Preflight (`agent-games.preflight.v1`) → `{ ok: true, protocolVersion: "v1" }`.
  - Every response body is signed with the same HMAC header.
  - `task_id` is treated as an idempotency key: a retry returns the byte-identical
    cached response.
- Decision logic — the 7 official checks, in order:
  1. `proof_vk != registered_vk` → REJECT `VK_SUBSTITUTION`
  2. `public_balance < minimum` → REJECT `THRESHOLD_MISMATCH`
  3. `proof_tx` already seen → REJECT `PROOF_REUSED` (seen-set persisted to disk;
     a proof reference is recorded once it passes checks 1–2)
  4. `current_block > expiry_block` → REJECT `EXPIRED_CONDITION`
  5. `recipient != condition_recipient` → REJECT `RECIPIENT_MISMATCH`
  6. `amount > max_transfer` → REJECT `AMOUNT_OVERFLOW`
  7. all pass → APPROVE `VALID_CONDITION`
  - Fails closed: malformed/unparseable tasks are rejected, never approved.
- `proof.js` — isolated Groth16 proof generation (snarkjs). Returns
  `{ proof, public_signals }`, or `null` gracefully if generation is unavailable —
  the decision is still returned. `PROOF_REUSED` responses carry no proof, per the
  official scoring note.
- `SPEC.md` — the full protocol spec extracted from the official /build guide and
  event page, including what the official pages do **not** specify.
- `test.js` — local end-to-end test harness (see below).

Response shape:
```json
{
  "decision": "APPROVE",
  "reason_code": "VALID_CONDITION",
  "proof": { "pi_a": ["…"], "pi_b": [["…"]], "pi_c": ["…"], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["… 13 field elements …"],
  "proof_tx": "0x…"
}
```

## Run it

Requirements: Node.js ≥ 18 (developed on Node 24).

```bash
npm install
./scripts/download-circuits.sh   # fetches gatekeeper.wasm + gatekeeper_final.zkey into ./circuits/
```

Set the environment (see `.env.example`):

| Variable | Required | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | for live play | From the dashboard: agent settings → **Rotate Secret** (shown once). Without it the agent runs in local test mode: signature checks skipped, responses unsigned. |
| `PORT` | no | Default `8787`. |
| `GATEKEEPER_WASM` / `GATEKEEPER_ZKEY` | no | Paths to circuit artifacts. Default: `../circuits/` relative to this folder; point them at `./circuits/…` after running the download script. |
| `GATEKEEPER_SALT` | no | Private circuit input; any value. Default `0`. |
| `SEEN_FILE` | no | proof_tx seen-set file. Default `./seen.json`. |
| `PROOF_ENABLED` | no | Set `0` to disable proof generation. |

```bash
AGENT_GAMES_HMAC_SECRET=<your-secret> GATEKEEPER_WASM=./circuits/gatekeeper.wasm GATEKEEPER_ZKEY=./circuits/gatekeeper_final.zkey npm start
```

## Test

```bash
npm test
```

Starts the server on a test port with a dummy local secret and replays: health,
preflight (incl. response-signature check), a bad-signature request (401), the valid
case, all 6 trap types, a proof-reuse second submission, and an idempotent retry.
**Current status: 22/22 checks pass**, including a real Groth16 proof attached to
every provable response (13 public signals each) and the seen-set persisted to disk.
(The secret in `test.js` is a throwaway fixture for local tests only.)

Independently re-verify a proof any time with:
`snarkjs groth16 verify verification_key.json public.json proof.json`
(the verification key is exported from the official zkey:
`snarkjs zkey export verificationkey gatekeeper_final.zkey verification_key.json`).

## What is proven working (locally, 15 Nov 2026)

- Full protocol surface: preflight handshake, HMAC verify-before-parse, signed
  responses, idempotent retries — all per the official /build guide (see `SPEC.md`).
- All 7 decision outcomes with the official reason codes.
- **Real Groth16 proof generation**: the circuit's input signal names are not
  published anywhere official; they were recovered from the compiled wasm by a
  prior participant and are confirmed here cryptographically — proofs generate in
  ~1–3 s and `snarkjs groth16 verify` returns OK against the official verification
  key. The circuit refuses to prove a wrong decision (assert failure), exactly as
  documented. Details and evidence: `SPEC.md` §9.

## What remains for go-live

1. **Create the public GitHub repo** `agentgames-proof-gatekeeper` under the
   personal account **ELVINO1806** (the registration form requires a public repo
   on a personal account; org repos are not supported) and push this tree.
2. **Host the agent at a public HTTPS endpoint** (standard port, no localhost /
   private IP / custom port; must not sleep — free tiers that sleep forfeit tasks).
   Any Node host works (e.g. a VPS, Fly.io, Render, Railway).
3. **Register the agent** in the Agent Games dashboard ("Register a new agent"):
   - AGENT NAME: your choice (public on the leaderboard)
   - EVENT TRACKS: check **Proof Gatekeeper**
   - REPOSITORY URL: `https://github.com/ELVINO1806/agentgames-proof-gatekeeper`
   - AGENT ENDPOINT: the full handler URL, e.g. `https://<your-host>/task`
     (the field is optional in the form, but the agent only becomes active after
     preflight passes against the registered endpoint)
4. **Rotate Secret** in the dashboard, copy the one-time plaintext into
   `AGENT_GAMES_HMAC_SECRET` on the host, restart the agent, and let the platform
   run preflight — it must pass before the agent is marked active.
5. **Run practice tasks first** (10/hour cap, unscored) and confirm two things the
   official docs leave unspecified, which only live traffic can settle:
   - the HMAC encoding (this implementation uses HMAC-SHA256 hex — if preflight
     fails with a signature error, revisit this first);
   - the `taskId` circuit-input mapping for string task ids such as `gk_24_9d1`
     (see `proof.js` header).
6. Scored rounds: Proof Gatekeeper runs 8 daily rounds, 13–21 Nov 2026,
   16:00–02:00 IST (17:30–03:30 WIB), 8 tasks per agent per day, 60 s deadline.

## Security notes

- Secrets come from environment variables only. Never commit `.env` or a filled
  secret; `.gitignore` already excludes `.env`, the seen-set, and local scratch.
- The agent never approves by default: any error, timeout, or uncertainty is a
  rejection.
- One competition account per person/team; one agent per owner in this event.
