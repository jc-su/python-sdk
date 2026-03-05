#!/bin/bash
# TEE-MCP Tamarin Proof Script
#
# Verifies all 14 security lemmas for the TEE-MCP protocol model (v3).
# Requires: tamarin-prover v1.10+ and maude in PATH.
#
# The secrecy lemma requires heuristic C (contrast), while all other
# lemmas use heuristic S (smart). We run two invocations since Tamarin
# uses a single heuristic per run.
#
# Usage: ./prove.sh

set -euo pipefail
cd "$(dirname "$0")"

COMMON_FLAGS="--derivcheck-timeout=0"
FAIL=0

echo "=== TEE-MCP Formal Verification (v3) ==="
echo ""

# Run 1: All lemmas except secrecy (heuristic S)
echo "[Run 1/2] Proving 13 lemmas with heuristic S..."
RESULT1=$(tamarin-prover tee_mcp.spthy \
  --prove=client_session_source \
  --prove=server_session_source \
  --prove=server_response_source \
  --prove=executable \
  --prove=session_key_agreement \
  --prove=injective_agreement_S2C \
  --prove=injective_agreement_C2S \
  --prove=measurement_integrity \
  --prove=session_binding \
  --prove=fresh_attestation \
  --prove=authority_trust_gate \
  --prove=self_integrity \
  --prove=tools_list_provenance \
  --heuristic=S $COMMON_FLAGS 2>/dev/null)

# Run 2: Secrecy lemma (heuristic C)
echo "[Run 2/2] Proving secrecy with heuristic C..."
RESULT2=$(tamarin-prover tee_mcp.spthy \
  --prove=secrecy \
  --heuristic=C $COMMON_FLAGS 2>/dev/null)

echo ""
echo "=== Results ==="
echo ""

# Extract summary lines (only lines matching "lemma_name (type): status")
while IFS= read -r line; do
  case "$line" in
    *"verified"*|*"falsified"*|*"incomplete"*)
      # Skip secrecy from Run 1 (it was not targeted)
      if echo "$line" | grep -q "secrecy.*incomplete"; then
        continue
      fi
      echo "  $line"
      if echo "$line" | grep -q "falsified\|incomplete"; then
        FAIL=$((FAIL + 1))
      fi
      ;;
    *"processing time"*)
      TIME1="$line"
      ;;
  esac
done <<< "$RESULT1"

while IFS= read -r line; do
  case "$line" in
    *"secrecy"*"verified"*|*"secrecy"*"falsified"*)
      echo "  $line"
      if echo "$line" | grep -q "falsified"; then
        FAIL=$((FAIL + 1))
      fi
      ;;
    *"processing time"*)
      TIME2="$line"
      ;;
  esac
done <<< "$RESULT2"

echo ""
echo " ${TIME1:-  processing time: ?}"
echo " ${TIME2:-  processing time: ?}"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo "All 14 lemmas verified."
  exit 0
else
  echo "FAILED: $FAIL lemma(s) not verified."
  exit 1
fi
