#!/usr/bin/env bash
set -euo pipefail

# Create a Google Workspace user via Admin SDK Directory API using
# a service account with Domain-Wide Delegation (DWD).
#
# Usage:
# ./create_gw_user.sh \
#   "delegated-admin@yourdomain.com" \
#   "new.user@yourdomain.com" \
#   "First" \
#   "Last" \
#   "/Students" \
#   "personal.email@gmail.com" \
#   "TempPassw0rd!"

DELEGATED_ADMIN_RAW="${1:?Delegated admin email required}"
PRIMARY_EMAIL_RAW="${2:?Primary Workspace email required}"
FIRST_NAME_RAW="${3:?First name required}"
LAST_NAME_RAW="${4:?Last name required}"
OU_PATH_RAW="${5:?OU path required (e.g., /Students)}"
RECOVERY_EMAIL_RAW="${6:?Recovery/personal email required}"
PASSWORD_RAW="${7:?Initial password required}"

CHANGE_PW_AT_NEXT_LOGIN="${CHANGE_PW_AT_NEXT_LOGIN:-true}" # true/false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SA_JSON="${SA_JSON:-${SCRIPT_DIR}/service_account.json}"
LOG_FILE="${SCRIPT_DIR}/gw_create_user.log"

# Log stdout+stderr to console + file
exec > >(tee -a "${LOG_FILE}") 2>&1
ts() { date '+%Y-%m-%d %H:%M:%S'; }
die() { echo "[$(ts)] ERROR: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
need jq
need openssl
need curl

# ---- sanitize inputs (remove CR, trim) ----
sanitize_trim() { printf '%s' "$1" | tr -d '\r' | xargs; }
sanitize_keep_spaces() { printf '%s' "$1" | tr -d '\r'; }

DELEGATED_ADMIN="$(sanitize_trim "${DELEGATED_ADMIN_RAW}")"
PRIMARY_EMAIL="$(sanitize_trim "${PRIMARY_EMAIL_RAW}")"
FIRST_NAME="$(sanitize_keep_spaces "${FIRST_NAME_RAW}")"
LAST_NAME="$(sanitize_keep_spaces "${LAST_NAME_RAW}")"
OU_PATH="$(sanitize_keep_spaces "${OU_PATH_RAW}")"
RECOVERY_EMAIL="$(sanitize_trim "${RECOVERY_EMAIL_RAW}")"
PASSWORD="$(sanitize_keep_spaces "${PASSWORD_RAW}")"

[[ -f "${SA_JSON}" ]] || die "Service account JSON not found at: ${SA_JSON}"

echo "[$(ts)] ----"
echo "[$(ts)] SA JSON: ${SA_JSON}"
echo "[$(ts)] Delegated admin: ${DELEGATED_ADMIN}"
echo "[$(ts)] Creating user: ${PRIMARY_EMAIL}"
echo "[$(ts)] Name: ${FIRST_NAME} ${LAST_NAME}"
echo "[$(ts)] OU: ${OU_PATH}"
echo "[$(ts)] Recovery email: ${RECOVERY_EMAIL}"
echo "[$(ts)] Log: ${LOG_FILE}"

CLIENT_EMAIL="$(jq -r '.client_email' "${SA_JSON}")"
TOKEN_URI="$(jq -r '.token_uri' "${SA_JSON}")"
PRIVATE_KEY="$(jq -r '.private_key' "${SA_JSON}")"

[[ -n "${CLIENT_EMAIL}" && "${CLIENT_EMAIL}" != "null" ]] || die "client_email missing in SA JSON"
[[ -n "${TOKEN_URI}" && "${TOKEN_URI}" != "null" ]] || die "token_uri missing in SA JSON"
[[ -n "${PRIVATE_KEY}" && "${PRIVATE_KEY}" != "null" ]] || die "private_key missing in SA JSON"

SCOPE="https://www.googleapis.com/auth/admin.directory.user"

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
    die "Failed to obtain access token. error='${err}' desc='${desc}'"
  fi

  printf '%s' "${token}"
}

ACCESS_TOKEN="$(get_access_token)"
echo "[$(ts)] Got access token."

# Build request body safely with jq
create_body="$(jq -n \
  --arg primaryEmail "${PRIMARY_EMAIL}" \
  --arg givenName "${FIRST_NAME}" \
  --arg familyName "${LAST_NAME}" \
  --arg password "${PASSWORD}" \
  --arg orgUnitPath "${OU_PATH}" \
  --arg recoveryEmail "${RECOVERY_EMAIL}" \
  --argjson changePasswordAtNextLogin "${CHANGE_PW_AT_NEXT_LOGIN}" \
  '{
    primaryEmail: $primaryEmail,
    name: { givenName: $givenName, familyName: $familyName },
    password: $password,
    changePasswordAtNextLogin: $changePasswordAtNextLogin,
    orgUnitPath: $orgUnitPath,
    recoveryEmail: $recoveryEmail
  }'
)"

echo "[$(ts)] Creating user via Directory API..."
echo "[$(ts)] Request body: ${create_body}"

create_resp="$(
  curl -sS -X POST "https://admin.googleapis.com/admin/directory/v1/users" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "${create_body}"
)"

if printf '%s' "${create_resp}" | jq -e '.error' >/dev/null 2>&1; then
  echo "[$(ts)] Create response: ${create_resp}"
  die "User creation failed."
fi

echo "[$(ts)] User created."

# Fallback: set recovery email via PATCH if not set on create
has_recovery="$(printf '%s' "${create_resp}" | jq -r '.recoveryEmail // empty')"
if [[ -z "${has_recovery}" ]]; then
  echo "[$(ts)] recoveryEmail not present; attempting PATCH..."
  patch_body="$(jq -n --arg recoveryEmail "${RECOVERY_EMAIL}" '{recoveryEmail:$recoveryEmail}')"

  patch_resp="$(
    curl -sS -X PATCH "https://admin.googleapis.com/admin/directory/v1/users/${PRIMARY_EMAIL}" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "${patch_body}"
  )"

  if printf '%s' "${patch_resp}" | jq -e '.error' >/dev/null 2>&1; then
    echo "[$(ts)] PATCH response: ${patch_resp}"
    die "User created, but failed to set recoveryEmail."
  fi
  echo "[$(ts)] recoveryEmail set via PATCH."
fi

echo "[$(ts)] Done."
