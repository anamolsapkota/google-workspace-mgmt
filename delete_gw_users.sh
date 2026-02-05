#!/usr/bin/env bash
set -euo pipefail

# Delete Google Workspace users via Admin SDK Directory API using a Service Account (DWD).
#
# Requires DWD scope:
#   https://www.googleapis.com/auth/admin.directory.user
#
# Usage (single):
#   ./delete_gw_users.sh --admin "delegated-admin@yourdomain.com" --email "user@yourdomain.com"
#
# Usage (bulk CSV):
#   ./delete_gw_users.sh --admin "delegated-admin@yourdomain.com" --csv "delete.csv"
#
# delete.csv header must be:
#   primary_email

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SA_JSON="${SA_JSON:-${SCRIPT_DIR}/service_account.json}"
LOG_FILE="${SCRIPT_DIR}/gw_delete_users.log"
OUT_CSV="${OUT_CSV:-${SCRIPT_DIR}/users_deleted.csv}"

exec > >(tee -a "${LOG_FILE}") 2>&1
ts() { date '+%Y-%m-%d %H:%M:%S'; }
die() { echo "[$(ts)] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need jq
need openssl
need curl
need awk
need tr
need mktemp

sanitize_trim() { printf '%s' "$1" | tr -d '\r' | xargs; }

usage() {
  cat <<EOF
Usage:
  Single:
    $0 --admin ADMIN --email EMAIL

  Bulk:
    $0 --admin ADMIN --csv delete.csv

CSV format:
  primary_email

Notes:
  - Service account JSON: ${SA_JSON}
  - Log file: ${LOG_FILE}
  - Output report CSV: ${OUT_CSV}
EOF
}

# --- args ---
DELEGATED_ADMIN=""
MODE=""
IN_CSV=""
PRIMARY_EMAIL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin) DELEGATED_ADMIN="$(sanitize_trim "${2:-}")"; shift 2 ;;
    --email) MODE="single"; PRIMARY_EMAIL="$(sanitize_trim "${2:-}")"; shift 2 ;;
    --csv) MODE="csv"; IN_CSV="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

[[ -n "${DELEGATED_ADMIN}" ]] || die "--admin is required"
[[ -f "${SA_JSON}" ]] || die "Service account JSON not found at: ${SA_JSON}"

CLIENT_EMAIL="$(jq -r '.client_email' "${SA_JSON}")"
TOKEN_URI="$(jq -r '.token_uri' "${SA_JSON}")"
PRIVATE_KEY="$(jq -r '.private_key' "${SA_JSON}")"
SA_CLIENT_ID="$(jq -r '.client_id' "${SA_JSON}")"

[[ -n "${CLIENT_EMAIL}" && "${CLIENT_EMAIL}" != "null" ]] || die "client_email missing in SA JSON"
[[ -n "${TOKEN_URI}" && "${TOKEN_URI}" != "null" ]] || die "token_uri missing in SA JSON"
[[ -n "${PRIVATE_KEY}" && "${PRIVATE_KEY}" != "null" ]] || die "private_key missing in SA JSON"

SCOPE="https://www.googleapis.com/auth/admin.directory.user"

b64url() { openssl base64 -e -A | tr '+/' '-_' | tr -d '='; }

get_access_token() {
  local sub_user="$1"
  local now exp header payload unsigned sig jwt resp token err desc
  now="$(date +%s)"
  exp="$((now + 3600))"
  header='{"alg":"RS256","typ":"JWT"}'

  payload="$(jq -n \
    --arg iss "${CLIENT_EMAIL}" \
    --arg scope "${SCOPE}" \
    --arg aud "${TOKEN_URI}" \
    --arg sub "${sub_user}" \
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
    echo "[$(ts)] Service account client_id to authorize in Admin Console DWD: ${SA_CLIENT_ID}"
    echo "[$(ts)] Requested scopes: ${SCOPE}"
    die "Failed to obtain access token for sub='${sub_user}'. error='${err}' desc='${desc}'"
  fi
  printf '%s' "${token}"
}

# --- report CSV (upsert) ---
csv_header='primary_email,deleted_at,status,message'

ensure_out_csv() {
  if [[ ! -f "${OUT_CSV}" ]]; then
    echo "${csv_header}" > "${OUT_CSV}"
  else
    head -n 1 "${OUT_CSV}" | grep -q '^primary_email,' || {
      local tmp; tmp="$(mktemp)"
      echo "${csv_header}" > "${tmp}"
      cat "${OUT_CSV}" >> "${tmp}"
      mv "${tmp}" "${OUT_CSV}"
    }
  fi
}

escape_csv_field() {
  local s="$1"
  if [[ "$s" == *'"'* ]]; then s="${s//\"/\"\"}"; fi
  if [[ "$s" == *','* || "$s" == *'"'* || "$s" == *$'\n'* ]]; then
    printf '"%s"' "$s"
  else
    printf '%s' "$s"
  fi
}

upsert_out_csv_row() {
  local email="$1" deleted_at="$2" status="$3" message="$4"
  ensure_out_csv
  local tmp; tmp="$(mktemp)"
  head -n 1 "${OUT_CSV}" > "${tmp}"
  awk -F',' -v target="${email}" 'NR==1{next} $1!=target {print}' "${OUT_CSV}" >> "${tmp}"
  printf "%s,%s,%s,%s\n" \
    "$(escape_csv_field "${email}")" \
    "$(escape_csv_field "${deleted_at}")" \
    "$(escape_csv_field "${status}")" \
    "$(escape_csv_field "${message}")" \
    >> "${tmp}"
  mv "${tmp}" "${OUT_CSV}"
}

delete_user_api() {
  local access_token="$1"
  local email="$2"

  # Capture HTTP status + body (body often empty on success)
  local resp http body
  resp="$(
    curl -sS -X DELETE "https://admin.googleapis.com/admin/directory/v1/users/${email}" \
      -H "Authorization: Bearer ${access_token}" \
      -H "Content-Type: application/json" \
      -w $'\n%{http_code}'
  )"
  http="$(printf '%s' "${resp}" | tail -n 1)"
  body="$(printf '%s' "${resp}" | sed '$d')"

  # Success is typically 204 No Content
  if [[ "${http}" == "204" || "${http}" == "200" ]]; then
    return 0
  fi

  # If error body exists, return it
  if [[ -n "${body}" ]]; then
    echo "${body}"
  else
    echo "{\"error\":{\"message\":\"HTTP ${http}\"}}"
  fi
  return 1
}

process_delete() {
  local token="$1"
  local email_raw="$2"
  local email deleted_at status message errjson

  email="$(sanitize_trim "${email_raw}")"
  [[ -n "${email}" ]] || return 0

  deleted_at="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$(ts)] Deleting user: ${email}"

  if delete_user_api "${token}" "${email}"; then
    status="DELETED"
    message="ok"
    echo "[$(ts)] Success: ${email} deleted."
  else
    status="FAILED"
    errjson="$(delete_user_api "${token}" "${email}" 2>/dev/null || true)"
    message="$(printf '%s' "${errjson}" | jq -r '.error.message // "unknown error"')"
    echo "[$(ts)] Failed: ${email} :: ${message}"
  fi

  upsert_out_csv_row "${email}" "${deleted_at}" "${status}" "${message}"
}

echo "[$(ts)] ----"
echo "[$(ts)] SA JSON: ${SA_JSON}"
echo "[$(ts)] Delegated admin: ${DELEGATED_ADMIN}"
echo "[$(ts)] Output report CSV: ${OUT_CSV}"
echo "[$(ts)] Log file: ${LOG_FILE}"

ACCESS_TOKEN="$(get_access_token "${DELEGATED_ADMIN}")"
echo "[$(ts)] Got access token."

ensure_out_csv

if [[ "${MODE}" == "single" ]]; then
  [[ -n "${PRIMARY_EMAIL}" ]] || die "--email is required for single mode"
  process_delete "${ACCESS_TOKEN}" "${PRIMARY_EMAIL}"
  echo "[$(ts)] Done. Report updated: ${OUT_CSV}"
  exit 0
fi

if [[ "${MODE}" == "csv" ]]; then
  [[ -n "${IN_CSV}" ]] || die "--csv path is required"
  [[ -f "${IN_CSV}" ]] || die "Input CSV not found: ${IN_CSV}"

  header="$(head -n 1 "${IN_CSV}" | tr -d '\r')"
  expected="primary_email"
  [[ "${header}" == "${expected}" ]] || die "Input CSV header must be exactly: ${expected}"

  echo "[$(ts)] Reading input CSV: ${IN_CSV}"
  tail -n +2 "${IN_CSV}" | while IFS=',' read -r c_email; do
    [[ -n "$(printf '%s' "${c_email}" | tr -d '[:space:]')" ]] || continue
    process_delete "${ACCESS_TOKEN}" "${c_email}"
  done

  echo "[$(ts)] Done. Report updated: ${OUT_CSV}"
  exit 0
fi

usage
die "You must provide either --email or --csv"
