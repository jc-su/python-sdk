# TEE-MCP Formal Model (Tamarin Prover)

Symbolic security model of the TEE-MCP attestation protocol (v3),
verified with the [Tamarin prover](https://tamarin-prover.github.io/).

## Prerequisites

- Tamarin prover v1.10+ (`tamarin-prover --version`)
- Maude in PATH (installed with Tamarin)

## Running

Verify all 14 lemmas:

```bash
./prove.sh
```

The script runs two passes: heuristic S for 13 lemmas, heuristic C for
secrecy (secrecy diverges under heuristic S).

Interactive exploration (web GUI on port 3001):

```bash
tamarin-prover interactive tee_mcp.spthy
```

Prove a single lemma:

```bash
tamarin-prover tee_mcp.spthy --prove=executable --heuristic=S --derivcheck-timeout=0
tamarin-prover tee_mcp.spthy --prove=secrecy --heuristic=C --derivcheck-timeout=0
```

## Model Overview

The model covers the full TEE-MCP protocol:

1. **Bootstrap** (Background-Check Model): Three-message key exchange with
   server-chosen challenge. All messages use standard attestation: fresh
   TDX quotes with `reportdata = h(<nonce, pubkey>)`.

2. **Session Establishment**: Session ID = SHA256(pk_C || pk_S || sd_C || sd_S || ekm),
   binding both parties' keys, bootstrap sig_data, and TLS EKM.

3. **Per-Call** (Passport Model): Session-bound HMAC-derived sig_data with
   monotonic counter, fresh TDX quote per call, RSA-OAEP key transport,
   AES-GCM payload encryption.

4. **Authority Trust Gate**: Centralized attestation-service issues trust
   verdicts for honest measurements. Server requires `!TrustVerdict` before
   accepting tool calls (models ToolTrustManager).

5. **Self-Integrity**: Server captures RTMR3 at bootstrap via linear
   `ServerIntegrity` fact. Each tool call consumes and reproduces it.
   `Server_Measurement_Changed` consumes without reproduction, blocking
   all subsequent calls.

6. **tools/list**: Lightweight session envelope (HMAC sig_data, no TDX
   quote) for trust metadata exchange.

### Attacker Model

- **Bootstrap**: Full Dolev-Yao (Out/In) — attacker intercepts, modifies, injects
- **Per-call**: TLS-protected (AuthSend/AuthRecv) — attacker cannot observe or tamper
- Attacker can run own TEE (different measurement) and compromise long-term keys

### Key Modeling Decisions

- **Standard attestation only** — no PSS signatures, no cached mode. Each
  attestation produces a fresh TDX quote with `reportdata = h(<nonce, pk>)`.
  This matches the implementation where cached attestation mode is removed.
- `tdx_quote/2 [private]` — only TEE rules can produce quotes
- Counter uniqueness via restriction (abstracts monotonic counter check)
- `!TrustVerdict(meas)` — persistent fact from `Authority_Trust_Verdict`,
  required by `Server_ToolResponse` to model the ToolTrustManager gate
- `ServerIntegrity(sid, meas)` — linear fact modeling RTMR3 self-check

### Changes from v2

- Removed `pss_sign`/`pss_verify`/`true_const` functions (no PSS in standard mode)
- All reportdata uses `h(<nonce, pk>)` pattern (was `h(<timestamp, pk>)`)
- Challenge-response uses fresh TDX quote (was PSS signature)
- Added `Authority_Trust_Verdict` rule and `!TrustVerdict` prerequisite
- Added `ServerIntegrity` linear fact and `Server_Measurement_Changed` rule
- Added tools/list rules (`Client_ToolsList`, `Server_ToolsList`, `Client_ToolsListResponse`)
- Client/server per-call rules use fresh TDX quotes (was PSS nonce signatures)
- 3 new lemmas: `authority_trust_gate`, `self_integrity`, `tools_list_provenance`

## Security Lemmas

All 14 lemmas verified automatically:

| # | Lemma | Property |
|---|-------|----------|
| P1 | `client_session_source` | Client calls imply honest client + session |
| P2 | `server_session_source` | Server accepts imply honest server + session |
| P3 | `server_response_source` | Server responses imply honest server + session |
| L1 | `executable` | Protocol can complete (sanity check) |
| L2 | `session_key_agreement` | Both parties agree on session parameters |
| L3 | `injective_agreement_S2C` | Server->Client injective agreement |
| L4 | `injective_agreement_C2S` | Client->Server injective agreement |
| L5 | `secrecy` | Payload secrecy (unless LTK compromise) |
| L6 | `measurement_integrity` | Calls require honest TEE measurement |
| L7 | `session_binding` | Session ID binds keys, nonces, and EKM |
| L8 | `fresh_attestation` | Distinct calls use distinct counters |
| L9 | `authority_trust_gate` | Server accepts only with authority verdict |
| L10 | `self_integrity` | Server accepts only with unchanged measurement |
| L11 | `tools_list_provenance` | tools/list responses imply session + server |

## File Structure

- `tee_mcp.spthy` — Tamarin theory (model + lemmas)
- `prove.sh` — Automated proof script
- `README.md` — This file

## Mapping to Implementation

See comments in `tee_mcp.spthy` for detailed mapping between Tamarin rules
and Python implementation:

| Tamarin Rule | Implementation |
|-------------|---------------|
| `Client_Init` | `TrustedClientSession.initialize()` |
| `Server_Init` | `TrustedServerSession._handle_initialize_request()` |
| `Client_Bootstrap` | `TrustedClientSession.initialize()` (response processing) |
| `Server_Bootstrap_Complete` | `TrustedServerSession._handle_initialized_tee()` |
| `Authority_Trust_Verdict` | `AttestationAuthorityClient.get_latest_verdict()` |
| `Server_Measurement_Changed` | Self-check failure in `open_request_envelope()` |
| `Client_ToolCall` | `TrustedClientSession._prepare_request_data()` (tools/call) |
| `Server_ToolResponse` | `TrustedServerSession._verify_and_decrypt_request()` |
| `Client_ToolResponse` | `TrustedClientSession._process_raw_response()` (tools/call) |
| `Client_ToolsList` | `TrustedClientSession._prepare_request_data()` (tools/list) |
| `Server_ToolsList` | `TrustedServerSession._send_response()` (tools/list) |
| `Client_ToolsListResponse` | `TrustedClientSession._process_raw_response()` (tools/list) |
