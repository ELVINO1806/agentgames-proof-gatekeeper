# Proof Gatekeeper — Official Spec (extracted 15 Nov 2026)

Sources (fetched as raw HTML, not just rendered-text crawl):
- `https://agentgames.zkverify.io/build` (Builder Field Guide) — raw copy in `../raw/build.html`, code blocks in `../raw/build-codeblocks.txt`
- `https://agentgames.zkverify.io/events/proof-gatekeeper` — raw copy in `../raw/gatekeeper.html`
- `https://agentgames.zkverify.io/api/circuit-info` — saved as `../circuit-info.json`

This file only records what the official pages state. Gaps are marked **GAP**.

---

## 1. Starter prompt (official, verbatim extract)

The /build page ships an official "Copy prompt" for AI coding tools (full text in
`../raw/build-codeblocks.txt`, block 0). Its protocol-relevant requirements:

- Platform NEVER runs participant code; agent = public HTTPS endpoint the platform POSTs signed tasks to.
- Per task: signed JSON envelope describing a transfer request → agent decides APPROVE or REJECT and
  returns a Groth16 ZK proof (generated locally with snarkjs) plus its public signals.
- Platform re-verifies the proof against its OWN registered verification key AND scores the decision.
- Build list from the prompt:
  1. HTTPS POST handler at the registered path (e.g. `/agent`).
  2. HMAC verification of every inbound request over the RAW request body vs the
     `x-agent-games-signature` header, BEFORE parsing JSON. Reject on mismatch.
  3. Decision logic: APPROVE only when EVERY item on the /build Security checklist passes;
     otherwise REJECT with a `reason_code`. Deterministic code makes the final call, never an LLM.
  4. Local Groth16 proof generation with snarkjs using the downloaded wasm/zkey.
  5. zkVerify submission (Kurier REST or zkVerifyJS); wait for **Finalized** before treating a proof as confirmed.
  6. Signed response `{ decision, reason_code, proof, public_signals }` with a valid
     `x-agent-games-signature` header over the raw response body.
  7. Preflight responder: reply `{ ok: true, protocolVersion: "v1" }`, signed.
  8. Local test harness replaying sample envelopes, plus `.env.example`.
- Secrets ONLY from env vars: `AGENT_GAMES_HMAC_SECRET` (dashboard "Rotate Secret"), `KURIER_API_KEY`.
  Fail closed on timeout/error/uncertainty (60 s hard deadline).

## 2. Endpoint registration (differs from study notes — more precise)

- Register the **full handler path** as the endpoint — e.g. `/agent`, not just the root domain.
  "The platform posts to the URL exactly as registered; a root path that returns 404 will fail
  preflight and every task." (Architecture step 01)
- After deploying: **rotate the agent secret on the platform dashboard**, copy the one-time
  plaintext, set it as env var **`AGENT_GAMES_HMAC_SECRET`**, restart the agent, then run preflight.
  Preflight must pass before the platform marks the agent active.
  (Note: official env var name is `AGENT_GAMES_HMAC_SECRET`, not `AGENT_GAMES_SECRET`.
  The study notes did not name the variable.)

## 3. Preflight handshake (NEW — not in study notes)

Request (platform → agent, signed, before any task):
```json
{
  "type": "agent-games.preflight.v1",
  "agent_id": "agt_...",
  "issued_at": "<issued-at>",
  "nonce": "abc123"
}
```
Required response — signed with `x-agent-games-signature`:
```json
{ "ok": true, "protocolVersion": "v1" }
```
"A mismatched or placeholder secret causes preflight to fail with a signature error."

## 4. Task envelope (Proof Gatekeeper, exact schema from /build)

```json
{
  "type":        "agent-games.proof-gatekeeper.v1",
  "task_id":     "gk_8d31_...",
  "mode":        "competition",
  "issued_at":   "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk":       "0x7d...91",
    "proof_vk":            "0x13...aa",
    "minimum":             "1000",
    "public_balance":      "1460",
    "expiry_block":        8430000,
    "current_block":       8420000,
    "recipient":           "0xDe42...9f01",
    "condition_recipient": "0xDe42...9f01",
    "amount":              "500",
    "max_transfer":        "1000",
    "proof_tx":            "0xa8...2c"
  }
}
```
Field types as shown: `minimum`, `public_balance`, `amount`, `max_transfer` are strings;
`expiry_block`, `current_block` are numbers. Addresses/VKs in the docs are truncated with
ellipses (`0xDe42...9f01`) — illustrative only, not real values.

## 5. Response schema

Minimal documented example (both /build and the event page):
```json
{
  "decision":    "REJECT",
  "reason_code": "VK_SUBSTITUTION",
  "proof_tx":    "0xa8...2c"
}
```
Full form per Architecture step 05 + starter prompt:
- Respond with the decision, a reason code, and — **on every provable task** — the Groth16
  `proof` and its `public_signals`. An omitted or invalid proof costs −2.
- `proof_tx` is an **optional** on-chain audit pointer.
- Every response is signed: `x-agent-games-signature` over the raw response body.
- Event page scoring note: "PROOF_REUSED tasks have no proof to submit and are excluded"
  (from the reliability-bonus calculation).

So the full response this agent returns:
`{ decision, reason_code, proof, public_signals, proof_tx }`
with `proof`/`public_signals` = null when no proof applies (PROOF_REUSED) or when local
proof generation is unavailable (see §9).

## 6. HMAC signing

Officially stated: HMAC over the **raw body**, header name `x-agent-games-signature`,
verified **before** JSON parsing; responses signed the same way over the raw response body.
Secret = platform-generated, revealed once via dashboard "Rotate Secret".

**GAP:** The official pages do NOT state the HMAC algorithm or encoding anywhere in the
fetched HTML (no "SHA-256"/"hex" mention). This implementation uses **HMAC-SHA256, hex
encoding** per the project brief / common convention. This must be confirmed against the
live preflight at go-live: if preflight fails with a signature error, the encoding is the
first thing to revisit.

## 7. Decision checks (Security checklist, /build §04) + trap map (event page)

Security checklist (approve only if ALL pass):
1. Verification key matches the key registered for this condition.
2. Circuit and proof system are the ones the task expects.
3. Public inputs prove the required threshold, recipient, and action.
4. Proof reference has not already been used for another task.
5. Verification reached a finalized state before approval.
6. Task signature and timestamp are valid before any work begins.

Trap encyclopedia (event page) → reason codes used by this agent, checked in the order
given in the project brief (which follows the event page's build checklist order:
VK → threshold → reuse → expiry → recipient → amount):
- All pass → APPROVE / `VALID_CONDITION`
- `proof_vk != registered_vk` → REJECT / `VK_SUBSTITUTION`
- `public_balance < minimum` → REJECT / `THRESHOLD_MISMATCH`
- `proof_tx` already in seen-set → REJECT / `PROOF_REUSED`
- `current_block > expiry_block` → REJECT / `EXPIRED_CONDITION`
- `recipient != condition_recipient` → REJECT / `RECIPIENT_MISMATCH`
- `amount > max_transfer` → REJECT / `AMOUNT_OVERFLOW`

Scoring (event page): correct ± decision +12; incorrect APPROVE −6; incorrect REJECT −3;
timeout −2; missing/invalid proof −2; reliability bonus +0…+5 pro-rated by share of provable
tasks whose proof verified. PROOF_REUSED tasks are excluded from the bonus denominator.

Seen-set semantics: a `proof_tx` is recorded as seen when a task carrying it is processed
and the proof is accepted into the pipeline (i.e. it passes the VK + threshold checks and
reaches the reuse check). A second submission of the same `proof_tx` is then PROOF_REUSED.

## 8. Circuit artifacts + zkVerify submission

- Circuits: Groth16 / BN128, Circom 2.x. Generate proofs locally with `snarkjs`; include the
  proof in the response.
- Gatekeeper `vk_hash` (registered on zkVerify mainnet):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  (matches `/api/circuit-info`; artifacts `gatekeeper.wasm`, `gatekeeper_final.zkey` —
  local copies in `../circuits/`.)
- Kurier (recommended): `POST https://api.kurier.xyz/api/v1/submit-proof/{KURIER_API_KEY}`
  ```json
  {
    "proofType": "groth16",
    "vkRegistered": true,
    "proofOptions": { "library": "snarkjs", "curve": "bn128" },
    "proofData": { "proof": {}, "publicSignals": [], "vk": "<registeredVkHash>" }
  }
  ```
  Poll job status: Submitted → IncludedInBlock → **Finalized** ("safe to return as confirmed").
- Alternative: zkVerifyJS (Volta session, direct chain interaction).

## 9. Circuit input signals — CONFIRMED locally (15 Nov 2026)

The /build page does NOT list the gatekeeper circuit's input signal names, and the
wasm/zkey do not contain them in plaintext (the wasm carries only FNV-1a hashes of the
names; `strings` on the wasm yields no signal names). A prior participant (Creator Track
write-up by @djarot, Medium, 14 Nov 2026) recovered the names by probing the wasm's
hash table. Those names were adopted here ONLY as a hypothesis and then **confirmed
cryptographically**: with them, `snarkjs groth16.fullProve` builds a witness and
`groth16.verify` returns OK against the official verification key exported from the
official zkey (nPublic = 13). A wrong name would make the witness calculator throw;
a wrong decision makes the circuit assert-fail (template `GatekeeperEvaluation`,
"Error in template GatekeeperEvaluation_79 line: 102").

Signals (13): `registeredVkHash`, `proofVkHash`, `minimum`, `publicBalance`,
`expiryBlock`, `currentBlock`, `recipient`, `conditionRecipient`, `amount`,
`maxTransfer`, `decision`, `taskId`, `salt` (private).

Encodings confirmed by the verifying proof (valid scenario: balance 1460 / minimum 1000,
amount 500 / cap 1000, recipient == condition, expiry 8430000 > current 8420000,
vk hash = registered gatekeeper hash, decision 1):
- vk hashes: 32-byte hex → BigInt → **reduced mod the BN128 field prime**.
- addresses: hex → BigInt → decimal string.
- `decision`: "1" = APPROVE, "0" = REJECT. The circuit enforces decision == 1 IFF all
  checks pass — a proof for a wrong decision cannot be generated at all.
- `salt`: free private input (verified with both "12345" and "0").
- Public signals order returned by fullProve (13): [0] derived evaluation hash,
  [1] registeredVkHash, [2] proofVkHash, [3] minimum, [4] publicBalance,
  [5] expiryBlock, [6] currentBlock, [7] recipient, [8] conditionRecipient,
  [9] amount, [10] maxTransfer, [11] taskId, [12] decision.
- Proof generation time: ~1–3 s per task (well inside the 60 s deadline).
  Reproduction: `work/verify-proof.js`, artifacts `work/proof.json`, `work/public.json`.

STILL UNVERIFIED (needs a live practice task at go-live):
- The `taskId` mapping. The envelope's `task_id` is a string like `gk_24_9d1`; the
  circuit takes a field element. `proof.js` passes numeric ids through and hashes
  other strings with sha256 into the field. If the platform computes the expected
  taskId public signal differently, platform-side re-verification would reject the
  proof even though it verifies locally. Confirm with practice mode before scored rounds.
- The HMAC algorithm/encoding (§6 GAP) — same remedy: live preflight.

## 10. Competition readiness checklist (/build §05, verbatim items)

1. Endpoint registered with the full handler path, not just the root domain
2. HMAC secret set from platform Rotate Secret — not a local placeholder
3. HMAC verification runs against the raw request body before parsing
4. All responses carry a valid x-agent-games-signature header
5. Preflight passes and agent is marked active on the dashboard
6. Responses always match the required schema
7. Secrets never appear in logs or model prompts
8. Timeouts fail closed instead of approving
9. Proof and transaction references are retained for disputes
10. Practice traps pass before entering a scored round

## 11. Registration form (from the user's dashboard screenshot, 15 Nov 09:39 WIB)

The real "Register a new agent" form fields:
- **AGENT NAME** — required; public on the leaderboard.
- **EVENT TRACKS** — required checkboxes; only two options exist in this form:
  Proof Gatekeeper and Steal the VFY. (Creator Track and Wildcard are NOT part of
  this agent-registration form.)
- **REPOSITORY URL** — **REQUIRED**. Must be a public GitHub repository on the
  user's **personal** account; organization repos are not supported.
  For this agent: `https://github.com/ELVINO1806/agentgames-proof-gatekeeper`
- **AGENT ENDPOINT** — **optional** in the form (can be supplied later; the /build
  guide still requires a live public HTTPS endpoint + passing preflight before the
  agent is marked active and can receive scored tasks).

Implication: a public GitHub repo is a hard prerequisite for registering the agent
at all — the repo must exist before the form can be submitted.

## 12. Differences vs study-notes.md

1. **Preflight handshake exists and is fully specified** (study notes only said "signed
   preflight"): exact request/response shapes in §3.
2. **Official env var name** is `AGENT_GAMES_HMAC_SECRET` (§2). Study notes named no variable.
3. **Endpoint must be registered with its full path** (e.g. `/agent`); root-only registration
   fails preflight (§2). Study notes only said "register endpoint URL".
4. **Response full form** includes `proof` + `public_signals` on every provable task;
   `proof_tx` is optional (§5). Study notes described the response only as
   "decision + reason_code".
5. **Kurier request body is documented** with an exact JSON shape (§8). Study notes only
   said "REST, register VK once, poll until Finalized".
6. **Secret flow refined**: register agent → deploy → dashboard **Rotate Secret** → set env →
   restart → preflight → active (§2). Study notes said the secret is shown at agent
   registration; the /build guide ties the usable secret to the Rotate Secret step.
7. **HMAC algorithm/encoding is NOT specified officially** (§6 GAP) — study notes did not
   flag this gap.
8. Confirmed unchanged: envelope fields, 7 traps + percentages, scoring, schedule,
   vk_hash, artifact filenames, 60 s deadline, fail-closed rule.
