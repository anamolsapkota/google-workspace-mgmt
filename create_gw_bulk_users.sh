#!/usr/bin/env bash
set -euo pipefail

# Create Google Workspace users via Admin SDK Directory API using
# a service account with Domain-Wide Delegation (DWD).
#
# Supports:
#  1) Single user creation via args
#  2) Bulk creation via input CSV
#
# Input fields required per user:
#   primary_email, first_name, last_name, org_unit, personal_email
#
# Password is auto-generated and recorded in users_created.csv (same directory).
#
# Usage (single):
# ./create_gw_users.sh \
#   --admin "delegated-admin@yourdomain.com" \
#   --email "new.user@yourdomain.com" \
#   --first "First" \
#   --last "Last" \
#   --ou "/Students" \
#   --personal "personal@gmail.com"
#
# Usage (bulk from CSV):
# ./create_gw_users.sh --admin "delegated-admin@yourdomain.com" --csv "input.csv"
#
# input.csv header must be:
# primary_email,first_name,last_name,org_unit,personal_email

CHANGE_PW_AT_NEXT_LOGIN="${CHANGE_PW_AT_NEXT_LOGIN:-true}" # true/false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SA_JSON="${SA_JSON:-${SCRIPT_DIR}/service_account.json}"
LOG_FILE="${SCRIPT_DIR}/gw_create_users.log"
OUT_CSV="${OUT_CSV:-${SCRIPT_DIR}/users_created.csv}"

exec > >(tee -a "${LOG_FILE}") 2>&1
ts() { date '+%Y-%m-%d %H:%M:%S'; }
die() { echo "[$(ts)] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need jq
need openssl
need curl
need awk
need sed
need tr

sanitize_trim() { printf '%s' "$1" | tr -d '\r' | xargs; }
sanitize_keep_spaces() { printf '%s' "$1" | tr -d '\r'; }

usage() {
  cat <<EOF
Usage:
  Single:
    $0 --admin ADMIN --email EMAIL --first FIRST --last LAST --ou OU --personal PERSONAL_EMAIL

  Bulk:
    $0 --admin ADMIN --csv input.csv

Notes:
  - Uses service_account.json in: ${SCRIPT_DIR}
  - Logs to: ${LOG_FILE}
  - Writes/updates output CSV: ${OUT_CSV}
EOF
}

# --- args ---
DELEGATED_ADMIN=""
MODE=""
IN_CSV=""

PRIMARY_EMAIL=""
FIRST_NAME=""
LAST_NAME=""
OU_PATH=""
PERSONAL_EMAIL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin) DELEGATED_ADMIN="$(sanitize_trim "${2:-}")"; shift 2 ;;
    --csv) MODE="csv"; IN_CSV="$(sanitize_keep_spaces "${2:-}")"; shift 2 ;;
    --email) MODE="single"; PRIMARY_EMAIL="$(sanitize_trim "${2:-}")"; shift 2 ;;
    --first) FIRST_NAME="$(sanitize_keep_spaces "${2:-}")"; shift 2 ;;
    --last) LAST_NAME="$(sanitize_keep_spaces "${2:-}")"; shift 2 ;;
    --ou) OU_PATH="$(sanitize_keep_spaces "${2:-}")"; shift 2 ;;
    --personal) PERSONAL_EMAIL="$(sanitize_trim "${2:-}")"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

[[ -n "${DELEGATED_ADMIN}" ]] || die "--admin is required"

[[ -f "${SA_JSON}" ]] || die "Service account JSON not found at: ${SA_JSON}"

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

# --- CSV helpers (simple + robust for commas-free fields) ---
# We assume fields do NOT contain commas. (Typical for emails + OU paths + names.)
csv_header='primary_email,first_name,last_name,org_unit,personal_email,password,created_at,status,message'

ensure_out_csv() {
  if [[ ! -f "${OUT_CSV}" ]]; then
    echo "${csv_header}" > "${OUT_CSV}"
  else
    # If file exists but header differs, keep it but ensure it has a header.
    head -n 1 "${OUT_CSV}" | grep -q '^primary_email,' || {
      tmp="$(mktemp)"
      echo "${csv_header}" > "${tmp}"
      cat "${OUT_CSV}" >> "${tmp}"
      mv "${tmp}" "${OUT_CSV}"
    }
  fi
}

escape_csv_field() {
  # Minimal CSV escaping: wrap in quotes if contains quote or comma; escape quotes by doubling
  local s="$1"
  if [[ "$s" == *'"'* ]]; then s="${s//\"/\"\"}"; fi
  if [[ "$s" == *','* || "$s" == *'"'* || "$s" == *$'\n'* ]]; then
    printf '"%s"' "$s"
  else
    printf '%s' "$s"
  fi
}

upsert_out_csv_row() {
  local email="$1" first="$2" last="$3" ou="$4" personal="$5" password="$6" created_at="$7" status="$8" message="$9"

  ensure_out_csv

  local tmp
  tmp="$(mktemp)"

  # Write header
  head -n 1 "${OUT_CSV}" > "${tmp}"

  # Rewrite existing rows excluding matching primary_email
  awk -F',' -v target="${email}" 'NR==1{next} $1!=target {print}' "${OUT_CSV}" >> "${tmp}"

  # Append updated/new row
  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(escape_csv_field "${email}")" \
    "$(escape_csv_field "${first}")" \
    "$(escape_csv_field "${last}")" \
    "$(escape_csv_field "${ou}")" \
    "$(escape_csv_field "${personal}")" \
    "$(escape_csv_field "${password}")" \
    "$(escape_csv_field "${created_at}")" \
    "$(escape_csv_field "${status}")" \
    "$(escape_csv_field "${message}")" \
    >> "${tmp}"

  mv "${tmp}" "${OUT_CSV}"
}

# --- password generator ---
gen_password() {
  # 16 chars, includes upper/lower/digits, avoids special chars that sometimes cause policy issues.
  # Ensures at least one uppercase, one lowercase, one digit.
  local upper lower digit rest
  upper="$(LC_ALL=C tr -dc 'A-Z' </dev/urandom | head -c 1)"
  lower="$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 1)"
  digit="$(LC_ALL=C tr -dc '0-9' </dev/urandom | head -c 1)"
  rest="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 13)"
  printf '%s%s%s%s\n' "${upper}" "${lower}" "${digit}" "${rest}"
}

create_user_api() {
  local access_token="$1"
  local email="$2" first="$3" last="$4" ou="$5" personal="$6" password="$7"

  local create_body create_resp

  create_body="$(jq -n \
    --arg primaryEmail "${email}" \
    --arg givenName "${first}" \
    --arg familyName "${last}" \
    --arg password "${password}" \
    --arg orgUnitPath "${ou}" \
    --arg recoveryEmail "${personal}" \
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

  create_resp="$(
    curl -sS -X POST "https://admin.googleapis.com/admin/directory/v1/users" \
      -H "Authorization: Bearer ${access_token}" \
      -H "Content-Type: application/json" \
      -d "${create_body}"
  )"

  if printf '%s' "${create_resp}" | jq -e '.error' >/dev/null 2>&1; then
    # Return error JSON
    printf '%s' "${create_resp}"
    return 1
  fi

  printf '%s' "${create_resp}"
  return 0
}

process_one_user() {
  local access_token="$1"
  local email_raw="$2" first_raw="$3" last_raw="$4" ou_raw="$5" personal_raw="$6"

  local email first last ou personal password created_at status message resp

  email="$(sanitize_trim "${email_raw}")"
  first="$(sanitize_keep_spaces "${first_raw}")"
  last="$(sanitize_keep_spaces "${last_raw}")"
  ou="$(sanitize_keep_spaces "${ou_raw}")"
  personal="$(sanitize_trim "${personal_raw}")"

  [[ -n "${email}" ]] || die "Missing primary_email"
  [[ -n "${first}" ]] || die "Missing first_name for ${email}"
  [[ -n "${last}" ]] || die "Missing last_name for ${email}"
  [[ -n "${ou}" ]] || die "Missing org_unit for ${email}"
  [[ -n "${personal}" ]] || die "Missing personal_email for ${email}"

  password="$(gen_password)"
  created_at="$(date '+%Y-%m-%d %H:%M:%S')"

  echo "[$(ts)] Creating: ${email} (${first} ${last}) OU=${ou} personal=${personal}"

  if resp="$(create_user_api "${access_token}" "${email}" "${first}" "${last}" "${ou}" "${personal}" "${password}")"; then
    status="CREATED"
    message="ok"
    echo "[$(ts)] Success: ${email}"
  else
    status="FAILED"
    # compact error message
    message="$(printf '%s' "${resp}" | jq -r '.error.message // "unknown error"')"
    echo "[$(ts)] Failed: ${email} :: ${message}"
  fi

  upsert_out_csv_row "${email}" "${first}" "${last}" "${ou}" "${personal}" "${password}" "${created_at}" "${status}" "${message}"
}

echo "[$(ts)] ----"
echo "[$(ts)] SA JSON: ${SA_JSON}"
echo "[$(ts)] Delegated admin: ${DELEGATED_ADMIN}"
echo "[$(ts)] Output CSV: ${OUT_CSV}"
echo "[$(ts)] Log file: ${LOG_FILE}"

ACCESS_TOKEN="$(get_access_token)"
echo "[$(ts)] Got access token."

ensure_out_csv

if [[ "${MODE}" == "single" ]]; then
  [[ -n "${PRIMARY_EMAIL}" ]] || die "--email is required for single mode"
  [[ -n "${FIRST_NAME}" ]] || die "--first is required for single mode"
  [[ -n "${LAST_NAME}" ]] || die "--last is required for single mode"
  [[ -n "${OU_PATH}" ]] || die "--ou is required for single mode"
  [[ -n "${PERSONAL_EMAIL}" ]] || die "--personal is required for single mode"

  process_one_user "${ACCESS_TOKEN}" "${PRIMARY_EMAIL}" "${FIRST_NAME}" "${LAST_NAME}" "${OU_PATH}" "${PERSONAL_EMAIL}"
  echo "[$(ts)] Done. CSV updated: ${OUT_CSV}"
  exit 0
fi

if [[ "${MODE}" == "csv" ]]; then
  [[ -n "${IN_CSV}" ]] || die "--csv path is required"
  [[ -f "${IN_CSV}" ]] || die "Input CSV not found: ${IN_CSV}"

  echo "[$(ts)] Reading input CSV: ${IN_CSV}"

  # Validate header
  header="$(head -n 1 "${IN_CSV}" | tr -d '\r')"
  expected="primary_email,first_name,last_name,org_unit,personal_email"
  [[ "${header}" == "${expected}" ]] || die "Input CSV header must be exactly: ${expected}"

  # Read lines (skip header)
  # NOTE: assumes no commas inside fields
  tail -n +2 "${IN_CSV}" | while IFS=',' read -r c_email c_first c_last c_ou c_personal; do
    # skip empty lines
    [[ -n "$(printf '%s' "${c_email}${c_first}${c_last}${c_ou}${c_personal}" | tr -d '[:space:]')" ]] || continue
    process_one_user "${ACCESS_TOKEN}" "${c_email}" "${c_first}" "${c_last}" "${c_ou}" "${c_personal}"
  done

  echo "[$(ts)] Done. CSV updated: ${OUT_CSV}"
  exit 0
fi

usage
die "You must provide either single user args (--email --first --last --ou --personal) OR --csv input.csv"
