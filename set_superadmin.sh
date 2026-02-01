#!/usr/bin/env bash
set -euo pipefail

# Grant Super Admin to a user using Admin SDK Directory API + Service Account (DWD).
#
# Usage:
# ./set_superadmin.sh "delegated-admin@yourdomain.com" "target-user@yourdomain.com"
#
# Optional:
#   TOKEN_ONLY=1  -> only mint token + do a lightweight API call to validate scopes.

DELEGATED_ADMIN_RAW="${1:?Delegated admin email required}"
TARGET_USER_EMAIL_RAW="${2:?Target user email required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SA_JSON="${SA_JSON:-${SCRIPT_DIR}/service_account.json}"
LOG_FILE="${SCRIPT_DIR}/set_superadmin.log"

exec > >(tee -a "${LOG_FILE}") 2>&1
ts() { date '+%Y-%m-%d %H:%M:%S'; }
die() { echo "[$(ts)] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need jq
need openssl
need curl

sanitize_trim() { printf '%s' "$1" | tr -d '\r' | xargs; }

DELEGATED_ADMIN="$(sanitize_trim "${DELEGATED_ADMIN_RAW}")"
TARGET_USER_EMAIL="$(sanitize_trim "${TARGET_USER_EMAIL_RAW}")"

[[ -f "${SA_JSON}" ]] || die "Service account JSON not found at: ${SA_JSON}"

CLIENT_EMAIL="$(jq -r '.client_email' "${SA_JSON}")"
TOKEN_URI="$(jq -r '.token_uri' "${SA_JSON}")"
PRIVATE_KEY="$(jq -r '.private_key' "${SA_JSON}")"
SA_CLIENT_ID="$(jq -r '.client_id' "${SA_JSON}")"
PROJECT_ID="$(jq -r '.project_id' "${SA_JSON}")"

[[ -n "${CLIENT_EMAIL}" && "${CLIENT_EMAIL}" != "null" ]] || die "client_email missing in SA JSON"
[[ -n "${TOKEN_URI}" && "${TOKEN_URI}" != "null" ]] || die "token_uri missing in SA JSON"
[[ -n "${PRIVATE_KEY}" && "${PRIVATE_KEY}" != "null" ]] || die "private_key missing in SA JSON"
[[ -n "${SA_CLIENT_ID}" && "${SA_CLIENT_ID}" != "null" ]] || die "client_id missing in SA JSON"

# Scopes required for:
# - listing roles + creating role assignments
# - reading users by email
SCOPE="https://www.googleapis.com/auth/admin.directory.rolemanagement https://www.googleapis.com/auth/admin.directory.user.readonly"

echo "[$(ts)] ----"
echo "[$(ts)] SA JSON: ${SA_JSON}"
echo "[$(ts)] Project: ${PROJECT_ID}"
echo "[$(ts)] Service Account client_email: ${CLIENT_EMAIL}"
echo "[$(ts)] Service Account client_id (must be authorized in Admin Console DWD): ${SA_CLIENT_ID}"
echo "[$(ts)] Delegated admin (sub): ${DELEGATED_ADMIN}"
echo "[$(ts)] Target user: ${TARGET_USER_EMAIL}"
echo "[$(ts)] Scopes: ${SCOPE}"
echo "[$(ts)] Log: ${LOG_FILE}"

b64url() { openssl base64 -e -A | tr '+/' '-_' | tr -d '='; }

get_access_token() {
  local now exp header payload unsigned sig jwt resp token err desc
  now="$(date +%s)"
  exp="$((now + 3600))"

  header='{"alg":"RS256","typ":"JWT"}'
  payload="$(jq -n \
    --arg iss "${CLIENT_EMAIL}" \
    --arg scope "${SCOPE}" \
    --arg aud "${TOKEN_URI}" \
    --arg sub "${DELEGATED_ADMIN}" \
    --argjson exp "${exp}" \
    --argjson iat "${now}" \
    '{iss:$iss, scope:$scope, aud:$aud, exp:$exp, iat:$iat, sub:$sub}')"

  unsigned="$(printf '%s' "${header}" | b64url).$(printf '%s' "${payload}" | b64url)"
  sig="$(
    printf '%s' "${unsigned}" \
      | openssl dgst -sha256 -sign <(printf '%s' "${PRIVATE_KEY}") \
      | b64url
  )"
  jwt="${unsigned}.${sig}"

  resp="$(
    curl -sS -X POST "${TOKEN_URI}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
      --data-urlencode "assertion=${jwt}"
  )"

  token="$(printf '%s' "${resp}" | jq -r '.access_token // empty')"
  if [[ -z "${token}" ]]; then
    err="$(printf '%s' "${resp}" | jq -r '.error // empty')"
    desc="$(printf '%s' "${resp}" | jq -r '.error_description // empty')"
    echo "[$(ts)] Token response: ${resp}"
    cat <<EOF >&2
[$(ts)] ACTION REQUIRED:
Authorize THIS client_id in Admin Console Domain-wide delegation:
  client_id: ${SA_CLIENT_ID}
And include THESE scopes (comma-separated):
  https://www.googleapis.com/auth/admin.directory.rolemanagement,
  https://www.googleapis.com/auth/admin.directory.user.readonly

Admin Console path:
  Security -> Access and data control -> API controls -> Domain-wide delegation -> Manage
EOF
    die "Failed to obtain access token. error='${err}' desc='${desc}'"
  fi

  printf '%s' "${token}"
}

ACCESS_TOKEN="$(get_access_token)"
echo "[$(ts)] Got access token."

# Optional: token-only validation (fast)
if [[ "${TOKEN_ONLY:-0}" == "1" ]]; then
  echo "[$(ts)] TOKEN_ONLY=1 set; validating scopes with a lightweight call..."
  test_resp="$(
    curl -sS "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles?maxResults=1" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}"
  )"
  if printf '%s' "${test_resp}" | jq -e '.error' >/dev/null 2>&1; then
    echo "[$(ts)] Validation response: ${test_resp}"
    die "Token minted but API call failed (likely permissions of delegated admin)."
  fi
  echo "[$(ts)] Token + scopes look OK."
  exit 0
fi

# 1) Get customerId
cust_resp="$(
  curl -sS "https://admin.googleapis.com/admin/directory/v1/customers/my_customer" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}"
)"
CUSTOMER_ID="$(printf '%s' "${cust_resp}" | jq -r '.id // empty')"
[[ -n "${CUSTOMER_ID}" ]] || { echo "[$(ts)] Customer response: ${cust_resp}"; die "Failed to get customerId."; }
echo "[$(ts)] customerId: ${CUSTOMER_ID}"

# 2) Find Super Admin roleId
roles_resp="$(
  curl -sS "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}"
)"
ROLE_ID="$(printf '%s' "${roles_resp}" | jq -r '.items[]? | select(.roleName=="Super Admin") | .roleId' | head -n 1)"
[[ -n "${ROLE_ID}" ]] || { echo "[$(ts)] Roles response: ${roles_resp}"; die "Could not find Super Admin roleId."; }
echo "[$(ts)] Super Admin roleId: ${ROLE_ID}"

# 3) Get target user id
user_resp="$(
  curl -sS "https://admin.googleapis.com/admin/directory/v1/users/${TARGET_USER_EMAIL}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}"
)"
TARGET_USER_ID="$(printf '%s' "${user_resp}" | jq -r '.id // empty')"
[[ -n "${TARGET_USER_ID}" ]] || { echo "[$(ts)] User response: ${user_resp}"; die "Could not find target user."; }
echo "[$(ts)] Target userId: ${TARGET_USER_ID}"

# 4) Create role assignment
assign_body="$(jq -n \
  --arg roleId "${ROLE_ID}" \
  --arg assignedTo "${TARGET_USER_ID}" \
  --arg scopeId "${CUSTOMER_ID}" \
  '{roleId:$roleId, assignedTo:$assignedTo, scopeType:"CUSTOMER", scopeId:$scopeId}')"

echo "[$(ts)] Creating role assignment..."
assign_resp="$(
  curl -sS -X POST "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${assign_body}"
)"

if printf '%s' "${assign_resp}" | jq -e '.error' >/dev/null 2>&1; then
  echo "[$(ts)] Role assignment response: ${assign_resp}"
  die "Failed to grant Super Admin."
fi

echo "[$(ts)] SUCCESS: ${TARGET_USER_EMAIL} granted Super Admin."
