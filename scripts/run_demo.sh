#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

pretty() {
  if command -v jq >/dev/null 2>&1; then jq .; else sed 's/{/{\n  /; s/,/,&\n  /g; s/}/\n}/'; fi
}

login() {
  curl -fsS -X POST "$BASE_URL/auth/token" -H 'Content-Type: application/json' \
    -d '{"tenantId":"org-a","email":"user-a@orga.test","password":"password"}'
}

token_from() {
  if command -v jq >/dev/null 2>&1; then jq -r '.accessToken'; else sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p'; fi
}

request() {
  local name="$1"
  shift
  curl -sS -D "$TMP_DIR/$name.headers" -o "$TMP_DIR/$name.body" "$@"
  pretty < "$TMP_DIR/$name.body"
}

printf '\nScenario 1 — Normal flow\n'
LOGIN="$(login)"
printf '%s\n' "$LOGIN" | pretty
TOKEN="$(printf '%s' "$LOGIN" | token_from)"
request normal_read -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/orders"
request normal_write -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}' "$BASE_URL/api/orders"
grep -qi '^X-TrustChain-Trust-Score: 100' "$TMP_DIR/normal_read.headers"
grep -qi '^X-TrustChain-Trust-Score: 100' "$TMP_DIR/normal_write.headers"
printf '✓ Normal flow: read + write both succeed, trust score stable at 100\n'

printf '\nScenario 2 — Trust decay + automatic downgrade\n'
request ip_change -H "Authorization: Bearer $TOKEN" -H 'X-Forwarded-For: 10.0.0.2' "$BASE_URL/api/orders"
grep -qi '^X-TrustChain-Trust-Score: 85' "$TMP_DIR/ip_change.headers"
for index in $(seq 1 20); do
  curl -fsS -o /dev/null -H "Authorization: Bearer $TOKEN" -H 'X-Forwarded-For: 10.0.0.2' "$BASE_URL/api/orders"
done
request decayed_write -X POST -H "Authorization: Bearer $TOKEN" -H 'X-Forwarded-For: 10.0.0.2' -H 'Content-Type: application/json' -d '{}' "$BASE_URL/api/orders"
grep -q 'trust_score_insufficient' "$TMP_DIR/decayed_write.body"
grep -qi '^X-TrustChain-Trust-Score: 65' "$TMP_DIR/decayed_write.headers"
request decayed_read -H "Authorization: Bearer $TOKEN" -H 'X-Forwarded-For: 10.0.0.2' "$BASE_URL/api/orders"
grep -qi '^HTTP/.* 200' "$TMP_DIR/decayed_read.headers"
printf '✓ Trust decay: write blocked at score 65 (< 70 threshold), reads still allowed\n'

printf '\nScenario 3 — Cross-tenant block\n'
LOGIN_TWO="$(login)"
TOKEN_TWO="$(printf '%s' "$LOGIN_TWO" | token_from)"
request cross_tenant -H "Authorization: Bearer $TOKEN_TWO" "$BASE_URL/api/orders?tenantId=org-b"
grep -q 'tenant_claim_mismatch' "$TMP_DIR/cross_tenant.body"
printf '✓ Cross-tenant: Org A token cannot access Org B data — blocked at token claim level\n'

printf '\nScenario 4 — Service-to-service impersonation attempt\n'
request service_cross -X POST -H 'Content-Type: application/json' -H 'X-Client-Cert-Fingerprint: mock-cert-fingerprint-order' \
  -d '{"requestingServiceId":"order-service","targetServiceId":"payment-service","delegatedUserId":"user-b","delegatedTenantId":"org-b","scopedAction":"read:orders"}' "$BASE_URL/service-token"
grep -q 'cross_tenant_impersonation_denied' "$TMP_DIR/service_cross.body"
request service_valid -X POST -H 'Content-Type: application/json' -H 'X-Client-Cert-Fingerprint: mock-cert-fingerprint-order' \
  -d '{"requestingServiceId":"order-service","targetServiceId":"payment-service","delegatedUserId":"user-a","delegatedTenantId":"org-a","scopedAction":"read:orders"}' "$BASE_URL/service-token"
if command -v jq >/dev/null 2>&1; then SERVICE_TOKEN="$(jq -r '.serviceToken' "$TMP_DIR/service_valid.body")"; else SERVICE_TOKEN="$(sed -n 's/.*"serviceToken":"\([^"]*\)".*/\1/p' "$TMP_DIR/service_valid.body")"; fi
request service_scope -X POST -H "Authorization: Bearer $SERVICE_TOKEN" -H 'X-Scoped-Action: write:payments' "$BASE_URL/internal/payments"
grep -q 'action_not_in_scope' "$TMP_DIR/service_scope.body"
printf '✓ Service tokens: cross-tenant impersonation blocked; out-of-scope action blocked\n'

printf '\nLast 20 audit events\n'
curl -fsS -H "Authorization: Bearer $TOKEN_TWO" "$BASE_URL/admin/audit?limit=20" | pretty
