# TEE-MCP Security Analysis

Formal threat model, security properties, and attack resistance analysis for the
TEE-MCP per-call attestation protocol.

## 1. System Model

TEE-MCP extends the Model Context Protocol (MCP) with hardware-attested,
encrypted communication using Intel TDX. The protocol operates between two
parties — an MCP Client (agent orchestrator) and an MCP Server (tool provider)
— each running inside a TDX Trust Domain.

### 1.1 IETF RATS Architecture Mapping (RFC 9334)

| TEE-MCP Component | RATS Role | Description |
|---|---|---|
| Container running MCP code | **Attester** | Generates TDX quotes binding identity + public key |
| `SecureEndpoint.verify_peer()` | **Verifier** | Validates reportdata binding, freshness, RTMR3, and authority verdict |
| `TrustedServerSession` / `TrustedClientSession` | **Relying Party** | Makes access decisions based on `AttestationResult` |
| TDX quote (hardware-signed) | **Evidence** | Hardware-signed attestation of runtime state |
| `AttestationResult` | **Attestation Result** | Verification outcome (valid/invalid + cgroup + RTMR3) |
| `attestation-service` | **Verifier Backend** | Centralized quote verification authority (fail-closed from MCP) |
| `VerificationResultCache` (authority-side) | **Appraisal Policy cache** | Short-TTL dedupe for identical `VerifyContainerEvidence` requests |
| `AttestationPolicy` | **Appraisal Policy** | Per-workload attestation requirements |
| `PolicyRegistry` | **Policy Administration** | Workload identity → policy resolution |

### 1.2 Attestation Model Composition

TEE-MCP uses a two-phase composition of two IETF RATS models:

| Phase | RATS Model | Freshness Mechanism |
|-------|-----------|---------------------|
| Bootstrap (`initialize`) | **Background-Check** | Server-chosen challenge (verifier nonce) |
| Per-call (`tools/call`) | **Passport** | Session-bound HMAC-derived `sig_data` with monotonic counter |

This composition is novel: no existing protocol combines Background-Check
bootstrap with Passport-model per-call attestation and session-derived freshness.
The SEAT WG discusses Background-Check and Passport independently; TEE-MCP
composes them with a clean transition point at session establishment.

## 2. Threat Model

### 2.1 Attacker Capabilities

We consider a Dolev-Yao-style network attacker who can:

- **Intercept**: Read all network traffic between client and server
- **Modify**: Alter, drop, reorder, or inject messages in transit
- **Replay**: Resend previously observed messages
- **Relay**: Forward messages between different sessions or endpoints
- **Own TEE**: Run their own TDX VM (with different measurements)
- **Control host OS**: Compromise the host outside the TDX VM boundary

The attacker **cannot**:

- Break TDX hardware security (compromise the TDX module or forge quotes)
- Break standard cryptographic primitives (RSA-4096, AES-256-GCM, SHA-256)
- Access memory inside a TDX Trust Domain from outside
- Forge TDX quotes that pass attestation-service backend verification with the victim's measurements

### 2.2 Trusted Components

| Component | Trust Assumption |
|-----------|-----------------|
| TDX hardware | Correct quote generation; measurements reflect actual code |
| `attestation-service` | Correct quote verification and policy verdict publication |
| TLS transport | Confidentiality and integrity of the byte stream (metadata protection) |
| RSA-4096, AES-256-GCM, SHA-256 | Standard cryptographic hardness |

### 2.3 Scope Limitations

- **Side channels**: TEE side-channel attacks (e.g., microarchitectural) are out
  of scope. TEE-MCP provides protocol-level security assuming the TEE is not
  compromised via side channels.
- **Denial of service**: An attacker can always drop messages; TEE-MCP does not
  provide availability guarantees.
- **Software bugs inside the TEE**: If the MCP server code inside the TDX VM
  has vulnerabilities, TEE-MCP cannot prevent exploitation. It guarantees that
  the *measured* code is the code that runs.

## 3. Formal Protocol Specification

### 3.1 Notation

```
Parties:    C = MCP Client,  S = MCP Server
E_X(n)      Attestation evidence from party X binding nonce n
              reportdata = H(n) || H(pk_X)
H(x)        SHA-256(x)
HMAC_k(m)   HMAC-SHA256 with key k over message m
{m}_{pk}    RSA-4096-OAEP encryption of m under public key pk
Enc_k(m)    AES-256-GCM encryption of m with key k
r ←$ S      r sampled uniformly at random from set S
||           Concatenation
```

### 3.2 Bootstrap Protocol (Background-Check Model)

```
1.  C → S:  E_C(sd_C), pk_C  [, workload_id]
      where sd_C ←$ {0,1}^256
            E_C binds: reportdata = H(sd_C) || H(pk_C)

2.  S → C:  E_S(sd_S), pk_S, ch
      where sd_S ←$ {0,1}^256,  ch ←$ {0,1}^256
            E_S binds: reportdata = H(sd_S) || H(pk_S)
            ch is the verifier-chosen challenge (Background-Check nonce)

3.  C → S:  E_C(ch), ch
      where E_C binds: reportdata = H(ch) || H(pk_C)
      Proves: C received ch from S and possesses sk_C inside TDX
```

### 3.3 Session Establishment

After message 3, both sides compute:

```
  sid = H(pk_C || pk_S || sd_C || sd_S  [|| EKM])

  where EKM = TLS-Exporter("EXPORTER-tee-mcp-channel-binding", ∅, 32)
        if TLS transport is available; omitted otherwise.

  Counter initialization:
    C: counter_C = 0,  peer_counter_C = 0
    S: counter_S = 0,  peer_counter_S = 0
```

### 3.4 Per-Call Protocol (Passport Model, Session-Bound)

For the i-th tool call from C and j-th response from S:

```
4.  C → S:  E_C(σ_i), ε_i, i, {name, args}_{pk_S}
      where ε_i ←$ {0,1}^256
            σ_i = HMAC_{sid}(ε_i || BE_64(i))
            i ≥ peer_counter_S  (monotonic, enforced by S)
      S verifies: σ_i' = HMAC_{sid}(ε_i || BE_64(i)), checks σ_i' = σ_i
      S decrypts: (AES_key, params) = RSA-OAEP-decrypt(sk_S, ciphertext)

5.  S → C:  E_S(σ_j), ε_j, j, Enc_{AES_key}(result)
      where ε_j ←$ {0,1}^256
            σ_j = HMAC_{sid}(ε_j || BE_64(j))
            AES_key reused from step 4 decryption (ResponseKey)
      C verifies: σ_j' = HMAC_{sid}(ε_j || BE_64(j)), checks σ_j' = σ_j
      C decrypts: result = AES-GCM-decrypt(AES_key, ciphertext)
```

### 3.5 Security Invariants

**INV-1 (Quote Binding)**: Every evidence `E_X(n)` contains a TDX quote whose
`reportdata` cryptographically binds `n` and `pk_X`. An attacker who does
not possess `sk_X` inside a TDX VM with matching measurements cannot produce
valid evidence.

**INV-2 (Session Uniqueness)**: `sid` includes both parties' public keys
and bootstrap sig_data. Two different sessions yield different `sid` values
with overwhelming probability (birthday bound on 256-bit `sid`).

**INV-3 (Counter Monotonicity)**: Within a session, the counter strictly
increases from the verifier's perspective. A message with
`i < peer_counter` is rejected. Gaps are allowed (see §5.5).

**INV-4 (HMAC Binding)**: `σ_i = HMAC_{sid}(ε_i || i)` can only be computed
by a party that knows `sid`. Since `sid` includes both public keys, both
bootstrap sig_data values, and optionally TLS EKM, an attacker who was not
party to the bootstrap (or on a different TLS connection) cannot derive valid
`sig_data`.

**INV-5 (Authority Verdict Gating)**: Every evidence verification requires a
`trusted` verdict from `attestation-service`; otherwise verification fails
closed. Cache reuse is centralized inside `attestation-service`.

## 4. Security Properties

### 4.1 Properties Provided

| # | Property | Mechanism | Code Reference |
|---|----------|-----------|----------------|
| P1 | **Platform Authenticity** | TDX quote verified by centralized authority RPC | `_verify_quote_via_authority()` + `AttestationAuthorityClient.verify_mcp_evidence()` |
| P2 | **Key Binding** | `reportdata = H(nonce) \|\| H(pubkey)` in TDX quote | `_compute_reportdata()` |
| P3 | **Bootstrap Freshness** | Server-chosen challenge in `initialized` evidence | `generate_bootstrap_challenge()` → `override_nonce` |
| P4 | **Per-Call Freshness** | `sig_data = HMAC_{sid}(entropy \|\| counter)` | `derive_sig_data()` |
| P5 | **Cross-Session Anti-Replay** | `sid = H(pk_C \|\| pk_S \|\| sd_C \|\| sd_S [\|\| EKM])` | `establish_session()` |
| P6 | **Within-Session Anti-Replay** | Monotonic counter: `counter >= peer_counter` | `verify_derived_sig_data()` |
| P7 | **TLS Channel Binding** | TLS EKM in `sid` when available | `tls_ekm.py`, `establish_session(tls_ekm=...)` |
| P8 | **Runtime Integrity** | Per-container RTMR3 in every quote | `allowed_rtmr3` check in `_verify_evidence()` |
| P9 | **State Change Detection** | RTMR3 transition policy with callback | `RTMR3TransitionPolicy`, `PeerStateChange` |
| P10 | **Message Confidentiality** | RSA-4096-OAEP + AES-256-GCM | `envelope.py` |
| P11 | **Message Integrity** | AES-GCM 128-bit auth tag | `aes.py` |
| P12 | **Workload Identity** | `workload_id` → policy registry | `_handle_initialize_request()` |

### 4.2 Properties NOT Provided

| Property | Reason |
|----------|--------|
| Forward secrecy | RSA key transport (no ephemeral DH). Each AES key is independent per call, but RSA private key compromise reveals all AES keys. |
| Delivery guarantee | Network attacker can drop messages; detection delegated to transport layer. |
| Post-compromise security | If TEE RSA private key extracted, past and future messages for that key are compromised. Key is protected by TDX VM boundary. |
| Side-channel resistance | Protocol-level property; hardware side channels out of scope. |
| Strict ordering | Counter allows gaps for pipelining. See §5.5. |

## 5. Attack Resistance Analysis

### 5.1 Replay Attacks

| Scenario | Prevented | Mechanism |
|----------|-----------|-----------|
| Replay init request to same server | Yes | Server generates fresh `sd_S` and `ch`; attacker cannot complete msg 3 without `sk_C` |
| Replay init request to different server | Yes | Different server has different `pk_S`; `sid` differs; HMAC `sig_data` invalid |
| Replay tool call within same session | Yes | Counter monotonicity: `counter < peer_counter` → rejected (`verify_derived_sig_data`) |
| Replay tool call across sessions | Yes | Different `sid` → different HMAC → `sig_data` mismatch |
| Replay tool call across TLS connections | Yes (with EKM) | `sid` includes TLS EKM; different TLS → different `sid` |

### 5.2 Relay / Man-in-the-Middle Attacks

| Scenario | Prevented | Mechanism |
|----------|-----------|-----------|
| Relay client evidence to attacker's server | Partial | Attacker obtains evidence but cannot decrypt tool params (encrypted to real `pk_S`). Cannot forge responses (no `sk_S`). |
| Relay across TLS connections | Yes (with EKM) | EKM in `sid` → wrong `sid` at relay target → HMAC `sig_data` invalid |
| Relay between two colluding endpoints | Yes | Unique TDX measurements per endpoint; RTMR3 mismatch at relay target |
| MitM during bootstrap | Yes | Challenge-response in msg 3: attacker cannot produce `E_C(ch)` without `sk_C` inside matching TDX VM |

### 5.3 Diversion Attacks (Identity Crisis)

Sardar et al. ("Identity Crisis in Confidential Computing", ASIACCS '26) show
that pre-handshake (RA-TLS) and intra-handshake attestation are vulnerable to
diversion attacks. TEE-MCP resists diversion via:

1. **Post-handshake design**: Evidence is exchanged after TLS handshake, within
   the MCP application protocol. The TLS channel provides initial authentication.
   No TLS protocol modifications needed.

2. **Bidirectional binding**: Both client and server attest. `sid` includes
   both `pk_C` and `pk_S`. A diverted server has different `pk_S` → different
   `sid` → HMAC `sig_data` invalid for subsequent calls.

3. **TLS EKM channel binding**: When available, `sid` includes EKM derived from
   the TLS master secret. TLS-terminating proxy or redirect produces different
   EKM → `sid` mismatch. This follows SEAT WG recommendation
   (draft-fossati-seat-expat §9.2, draft-usama-seat-intra-vs-post-02 §8).

### 5.4 Forgery Attacks

| Scenario | Prevented | Mechanism |
|----------|-----------|-----------|
| Forge TDX quote without TDX hardware | Yes | Authority backend verifies hardware quote chain |
| Forge evidence with different key | Yes | `reportdata = H(nonce) \|\| H(pubkey)` — different key → reportdata mismatch |
| Use attacker's TDX VM with different code | Detected | RTMR3 differs; `allowed_rtmr3` rejects |

### 5.5 Reordering and Message Dropping

**Design choice**: TEE-MCP uses a **monotonic counter with gaps allowed**.

The counter check is `counter >= _peer_call_counter` (not strict equality):

- **Dropped messages tolerated**: If the network drops message `i=5`, message
  `i=6` is still accepted. Counter advances to 7.
- **Late arrival rejected**: After accepting `i=6`, message `i=5` arriving late
  is rejected (`5 < 7`).
- **Strict replay prevented**: Any `i < peer_counter` is rejected.

**Rationale**: MCP operates over HTTP (Streamable HTTP transport), which may
pipeline requests. Requiring strict sequential delivery would break pipelining.
TCP provides in-order delivery for most cases; the counter provides a safety
net against protocol-level replay.

**Guarantee**: TEE-MCP provides **message authenticity and monotonic ordering**
but not **delivery guarantees**. Delivery is delegated to the transport layer.

### 5.6 Runtime State Changes

When a peer's container state changes (code update, model reload, tool
installation), RTMR3 changes. TEE-MCP detects this via RTMR3 transition
policy:

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `REJECT` | Session terminated | High-security: no runtime changes |
| `LOG_AND_ACCEPT` | Change logged, session continues | Default: monitoring |
| `ACCEPT` | Silent acceptance | Permissive environments |

A callback (`on_peer_state_change`) enables application-level decisions:
- Allow known upgrade paths (old RTMR3 → new RTMR3)
- Reject downgrades
- Trigger re-attestation with stricter parameters

This implements **dynamic attestation** as identified in
[draft-jiang-seat-dynamic-attestation](https://datatracker.ietf.org/doc/html/draft-jiang-seat-dynamic-attestation-00)
for AI agent systems.

### 5.7 Stale Quote Attacks

An attacker might attempt to use a valid but old TDX quote:

| Layer | Protection | Mechanism |
|-------|-----------|-----------|
| Evidence freshness | `timestamp_ms` within `MAX_AGE_MS` (5 min) | `_verify_evidence()` |
| Authority verdict | Cache miss requires fresh authority decision | `_verify_quote_via_authority()` |
| Authority verify cache TTL | short-lived request memoization inside authority | `VerificationResultCache` |
| RTMR3 allowlist | Measured runtime state checked on every message | `_verify_evidence()` |

## 6. Comparison with Existing Approaches

### 6.1 Protocol Comparison

| Property | RA-TLS | draft-fossati-seat-expat | SCONE | **TEE-MCP** |
|----------|--------|--------------------------|-------|-------------|
| Attestation timing | Pre-handshake | Post-handshake | Post-handshake | **Post-handshake** |
| Attestation frequency | Once (TLS setup) | Once + optional re-attest | Once | **Per tool call** |
| Channel binding | None (cert ext.) | EKM (TLS Exporter) | TLS cert | **EKM + session HMAC** |
| Replay resistance | Timestamp only | EKM freshness | TLS nonce | **Session HMAC + counter** |
| Replay attack known? | Yes (Sardar et al.) | No known | Not analyzed | **No known** |
| Diversion attack known? | Yes (Identity Crisis) | No (post-handshake) | Not analyzed | **No (post-HS + EKM)** |
| Relay attack known? | N/A | No (EKM binding) | N/A | **No (EKM + session)** |
| Runtime state detection | No | No | No | **Yes (RTMR3 transition)** |
| Quote reuse (attester) | No | No | No | **Legacy-only (not used in authority-only flow)** |
| Quote reuse (verifier) | No | No | No | **No (moved to authority-side cache)** |
| TLS changes needed | X.509 extension | Exported Authenticator | Custom protocol | **None (app layer)** |
| RATS model | Pre-handshake | Background-Check | Background-Check | **Background-Check (bootstrap) + Passport (per-call)** |

### 6.2 Sardar Taxonomy Classification

Per [draft-usama-seat-intra-vs-post-02](https://datatracker.ietf.org/doc/html/draft-usama-seat-intra-vs-post-02):

| Category | TLS Changes | Known Attacks | TEE-MCP |
|----------|------------|---------------|---------|
| **Pre-handshake** | None (X.509) | Replay, diversion | — |
| **Intra-handshake** | Invasive (key schedule) | Diversion, relay | — |
| **Post-handshake** | None | **None known** | **TEE-MCP is here** |

TEE-MCP is strictly post-handshake: evidence is exchanged within the MCP
application protocol after TLS establishment. No TLS library modifications
required. EKM is extracted read-only via `SSL_export_keying_material()`.

## 7. Authority-Side Verification Caching

In authority-only mode, quote/evidence caching is centralized in
`attestation-service`:

- MCP always sends evidence to authority for verification.
- Authority uses a short-TTL request cache keyed by full verification input
  and an invalidation epoch.
- Concurrent identical requests are deduplicated with a singleflight path.

Security boundary:

- MCP still fails closed on authority errors or non-`trusted` verdicts.
- Freshness/reportdata/RTMR3 checks remain enforced by verifier logic.
- `ToolTrustManager` remains the runtime hot path for per-tool gating and
  revocation response.

## 8. TLS Channel Binding via EKM

### 8.1 Mechanism

```python
EKM = SSL_export_keying_material(
    ssl_ptr,
    label  = b"EXPORTER-tee-mcp-channel-binding",
    context = NULL,
    length  = 32
)
sid = SHA256(pk_C || pk_S || sd_C || sd_S || EKM)
```

### 8.2 Graceful Degradation

| Transport | EKM | Binding Strength |
|-----------|-----|------------------|
| TLS (HTTPS) with libssl | Yes | **Full**: session + TLS |
| TLS but EKM extraction fails | No | **Session-only**: app-layer binding |
| stdio (local pipe) | N/A | **Session-only**: no network relay |
| Plain HTTP | No | **Session-only**: TLS strongly recommended |

### 8.3 Propagation Path

**Server**: `connection_made()` → `extract_ekm(ssl_object)` →
`scope["state"]["tls_ekm"]` → `tls_ekm_var` ContextVar →
`establish_session(tls_ekm=ekm)`

**Client**: `httpcore._connect()` hook → `extract_ekm(ssl_object)` →
`tls_ekm_var` ContextVar → `establish_session(tls_ekm=ekm)`

### 8.4 IETF Alignment

Follows SEAT WG recommendation (draft-fossati-seat-expat, draft-usama-seat-intra-vs-post-02 §8):

> Post-handshake attestation avoids replay attacks by using fresh attestation
> nonce. Moreover, it avoids diversion and relay attacks by binding the Evidence
> to the underlying TLS connection, such as using Exported Keying Material (EKM).

## 9. Workload Identity and Policy

### 9.1 Workload Identity Scope

Inspired by [draft-rosomakho-tls-wimse-cert-hint-01](https://datatracker.ietf.org/doc/html/draft-rosomakho-tls-wimse-cert-hint-01):

```json
{ "_meta": { "tee": { "workload_id": "mcp://agent.example.com", ... } } }
```

The `workload_id` is an **unauthenticated hint** in message 1 (analogous to
TLS SNI). It becomes **authenticated** after attestation: the TDX quote binds
the sender's key and measurements, and the policy registry maps `workload_id`
to expected measurements.

### 9.2 Per-Container RTMR3 as Cryptographic Workload Identity

Unlike URI-based identity (WIMSE/SPIFFE), RTMR3 is a **cryptographically
measured** identity derived from the actual container contents:

```
rtmr3 = SHA384(rtmr3_prev || file_digest)   for each file loaded
```

This provides stronger guarantees than declarative identity: the identity IS
the code, not a label attached to the code. Combined with `PolicyRegistry`,
this enables:

1. **Per-workload attestation policies** — different agents get different rules
2. **Runtime posture monitoring** — RTMR3 transition detection
3. **Continuous verification** — every operation carries fresh evidence

## 10. Novel Contributions

1. **Hybrid Background-Check + Passport composition** — First protocol to
   compose verifier-chosen challenge at bootstrap with self-attested
   session-bound evidence at per-operation granularity.

2. **Per-call attestation for AI agent communication** — Operation-triggered
   attestation (SEAT use case 4) with centralized authority verification and
   fail-closed enforcement.

3. **Centralized verification cache** — authority-side short-TTL caching and
   in-flight request dedupe amortize repeated verification bursts without
   splitting trust logic into MCP peers.

4. **RTMR3 transition detection** — Runtime state change monitoring
   extending attestation from "verify once" to "detect state changes per
   operation", enabling dynamic attestation for AI agents.

5. **Per-container RTMR3 as workload identity** — Cryptographically measured
   identity (hash chain of loaded files) bound in TDX quotes, providing
   finer granularity than VM-level attestation.

6. **Application-layer post-handshake attestation** — No TLS modifications;
   EKM extracted read-only; applicable to existing MCP deployments.

## 11. References

- [RFC 9334](https://datatracker.ietf.org/doc/html/rfc9334) — Remote ATtestation procedureS (RATS) Architecture
- [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705) — Keying Material Exporters for TLS
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266) — Channel Bindings for TLS 1.3
- [RFC 9261](https://www.rfc-editor.org/rfc/rfc9261) — Exported Authenticators in TLS
- [draft-usama-seat-intra-vs-post-02](https://datatracker.ietf.org/doc/html/draft-usama-seat-intra-vs-post-02) — Pre-, Intra- and Post-handshake Attestation
- [draft-fossati-seat-expat](https://tls-attestation.github.io/exported-attestation/draft-fossati-seat-expat.html) — Remote Attestation with Exported Authenticators
- [draft-rosomakho-tls-wimse-cert-hint-01](https://datatracker.ietf.org/doc/html/draft-rosomakho-tls-wimse-cert-hint-01) — Workload Identifier Scope Hint
- [draft-jiang-seat-dynamic-attestation](https://datatracker.ietf.org/doc/html/draft-jiang-seat-dynamic-attestation-00) — Dynamic Attestation for AI Agent Communication
- [draft-mihalcea-seat-use-cases-01](https://datatracker.ietf.org/doc/html/draft-mihalcea-seat-use-cases-01) — Use Cases for Integrating Remote Attestation with Secure Channel Protocols
- [Identity Crisis](https://www.researchgate.net/publication/398839141) — Formal Analysis of Attested TLS (Sardar et al., ASIACCS '26)
- [SoK: Attestation in Confidential Computing](https://www.researchgate.net/publication/367284929) — Sardar, Fossati, Frost, 2023
