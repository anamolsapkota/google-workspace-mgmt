#!/usr/bin/env bash
set -euo pipefail

# Create Google Workspace users via Admin SDK Directory API using a Service Account (DWD),
# generate a TEMP password, force change at next login, write results to CSV,
# and send onboarding email via Gmail SMTP (credentials from .env).
#
# CSV input header must be:
# primary_email,first_name,last_name,org_unit,personal_email

CHANGE_PW_AT_NEXT_LOGIN="${CHANGE_PW_AT_NEXT_LOGIN:-true}" # true/false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SA_JSON="${SA_JSON:-${SCRIPT_DIR}/service_account.json}"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"
TEMPLATE_DIR="${SCRIPT_DIR}/email_templates"
EMAIL_TEMPLATE="${EMAIL_TEMPLATE:-${TEMPLATE_DIR}/kusoed_account_created.txt}"

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
need mktemp

sanitize_trim() { printf '%s' "$1" | tr -d '\r' | xargs; }
sanitize_keep_spaces() { printf '%s' "$1" | tr -d '\r'; }

usage() {
  cat <<EOF
Usage:
  Single:
    $0 --admin ADMIN --email EMAIL --first FIRST --last LAST --ou OU --personal PERSONAL_EMAIL

  Bulk:
    $0 --admin ADMIN --csv input.csv

Required CSV header:
  primary_email,first_name,last_name,org_unit,personal_email

Files expected in: ${SCRIPT_DIR}
  - service_account.json
  - .env
  - email_templates/kusoed_account_created.txt

Outputs:
  - Log: ${LOG_FILE}
  - CSV: ${OUT_CSV}
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
[[ -f "${ENV_FILE}" ]] || die ".env not found at: ${ENV_FILE}"
[[ -f "${EMAIL_TEMPLATE}" ]] || die "Email template not found at: ${EMAIL_TEMPLATE}"

# Load .env (simple KEY=VALUE lines)
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

: "${SMTP_HOST:?Missing SMTP_HOST in .env}"
: "${SMTP_PORT:?Missing SMTP_PORT in .env}"   # 465 recommended
: "${SMTP_USER:?Missing SMTP_USER in .env}"
: "${SMTP_PASS:?Missing SMTP_PASS in .env}"
: "${SMTP_FROM:?Missing SMTP_FROM in .env}"

CLIENT_EMAIL="$(jq -r '.client_email' "${SA_JSON}")"
TOKEN_URI="$(jq -r '.token_uri' "${SA_JSON}")"
PRIVATE_KEY="$(jq -r '.private_key' "${SA_JSON}")"
SA_CLIENT_ID="$(jq -r '.client_id' "${SA_JSON}")"

[[ -n "${CLIENT_EMAIL}" && "${CLIENT_EMAIL}" != "null" ]] || die "client_email missing in SA JSON"
[[ -n "${TOKEN_URI}" && "${TOKEN_URI}" != "null" ]] || die "token_uri missing in SA JSON"
[[ -n "${PRIVATE_KEY}" && "${PRIVATE_KEY}" != "null" ]] || die "private_key missing in SA JSON"
[[ -n "${SA_CLIENT_ID}" && "${SA_CLIENT_ID}" != "null" ]] || die "client_id missing in SA JSON"

# Directory scope only
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
    echo "[$(ts)] Authorize this client_id in Admin Console DWD: ${SA_CLIENT_ID}"
    echo "[$(ts)] Requested scopes: ${SCOPE}"
    die "Failed to obtain access token for sub='${sub_user}'. error='${err}' desc='${desc}'"
  fi

  printf '%s' "${token}"
}

# --- CSV (upsert) ---
csv_header='primary_email,first_name,last_name,org_unit,personal_email,temp_password,created_at,status,message'

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
  local email="$1" first="$2" last="$3" ou="$4" personal="$5" pass="$6" created_at="$7" status="$8" message="$9"

  ensure_out_csv
  local tmp; tmp="$(mktemp)"

  head -n 1 "${OUT_CSV}" > "${tmp}"
  awk -F',' -v target="${email}" 'NR==1{next} $1!=target {print}' "${OUT_CSV}" >> "${tmp}"

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(escape_csv_field "${email}")" \
    "$(escape_csv_field "${first}")" \
    "$(escape_csv_field "${last}")" \
    "$(escape_csv_field "${ou}")" \
    "$(escape_csv_field "${personal}")" \
    "$(escape_csv_field "${pass}")" \
    "$(escape_csv_field "${created_at}")" \
    "$(escape_csv_field "${status}")" \
    "$(escape_csv_field "${message}")" \
    >> "${tmp}"

  mv "${tmp}" "${OUT_CSV}"
}

# --- temp password generator ---
gen_password() {
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
    printf '%s' "${create_resp}"
    return 1
  fi

  printf '%s' "${create_resp}"
  return 0
}

make_signin_link() {
  local primary_email="$1"
  printf 'https://accounts.google.com/AccountChooser?Email=%s&continue=https://mail.google.com/\n' "${primary_email}"
}

render_template() {
  local first="$1" last="$2" primary="$3" signin_link="$4" temp_password="$5"
  sed \
    -e "s/{{FIRST_NAME}}/${first//\//\\/}/g" \
    -e "s/{{LAST_NAME}}/${last//\//\\/}/g" \
    -e "s/{{PRIMARY_EMAIL}}/${primary//\//\\/}/g" \
    -e "s#{{SIGNIN_LINK}}#${signin_link}#g" \
    -e "s/{{TEMP_PASSWORD}}/${temp_password//\//\\/}/g" \
    "${EMAIL_TEMPLATE}"
}

smtp_send_mail() {
  local to_email="$1"
  local subject="$2"
  local body="$3"

  local msg_file
  msg_file="$(mktemp)"
  chmod 600 "${msg_file}"

  {
    echo "From: ${SMTP_FROM}"
    echo "To: ${to_email}"
    echo "Subject: ${subject}"
    echo "MIME-Version: 1.0"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo
    printf '%s\n' "${body}"
  } > "${msg_file}"

  curl -sS --ssl-reqd \
    --url "smtps://${SMTP_HOST}:${SMTP_PORT}" \
    --user "${SMTP_USER}:${SMTP_PASS}" \
    --mail-from "${SMTP_USER}" \
    --mail-rcpt "${to_email}" \
    --upload-file "${msg_file}" >/dev/null

  rm -f "${msg_file}"
}

process_one_user() {
  local dir_token="$1"
  local email_raw="$2" first_raw="$3" last_raw="$4" ou_raw="$5" personal_raw="$6"

  local email first last ou personal temp_pass created_at status message resp rendered subject body signin_link

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

  temp_pass="$(gen_password)"
  created_at="$(date '+%Y-%m-%d %H:%M:%S')"

  echo "[$(ts)] Creating: ${email} (${first} ${last}) OU=${ou} personal=${personal}"

  if resp="$(create_user_api "${dir_token}" "${email}" "${first}" "${last}" "${ou}" "${personal}" "${temp_pass}")"; then
    status="CREATED"
    message="ok"
    echo "[$(ts)] Success: ${email}"

    signin_link="$(make_signin_link "${email}")"
    rendered="$(render_template "${first}" "${last}" "${email}" "${signin_link}" "${temp_pass}")"
    subject="$(printf '%s\n' "${rendered}" | awk -F': ' 'tolower($1)=="subject"{print $2; exit}')"
    [[ -n "${subject}" ]] || subject="KUSOED – Google Workspace Account Access"
    body="$(printf '%s\n' "${rendered}" | awk 'tolower($1)!="subject:"{print}')"

    if smtp_send_mail "${personal}" "${subject}" "${body}"; then
      echo "[$(ts)] Onboarding email sent to: ${personal}"
    else
      echo "[$(ts)] WARNING: Failed to send onboarding email to: ${personal}"
      message="ok (email failed)"
    fi
  else
    status="FAILED"
    message="$(printf '%s' "${resp}" | jq -r '.error.message // "unknown error"')"
    echo "[$(ts)] Failed: ${email} :: ${message}"
  fi

  upsert_out_csv_row "${email}" "${first}" "${last}" "${ou}" "${personal}" "${temp_pass}" "${created_at}" "${status}" "${message}"
}

echo "[$(ts)] ----"
echo "[$(ts)] SA JSON: ${SA_JSON}"
echo "[$(ts)] Service account client_id: ${SA_CLIENT_ID}"
echo "[$(ts)] Delegated admin (Directory): ${DELEGATED_ADMIN}"
echo "[$(ts)] SMTP From: ${SMTP_FROM}"
echo "[$(ts)] SMTP User: ${SMTP_USER}"
echo "[$(ts)] Template: ${EMAIL_TEMPLATE}"
echo "[$(ts)] Output CSV: ${OUT_CSV}"
echo "[$(ts)] Log file: ${LOG_FILE}"

DIR_TOKEN="$(get_access_token "${DELEGATED_ADMIN}")"
echo "[$(ts)] Got Directory token."

ensure_out_csv

if [[ "${MODE}" == "single" ]]; then
  [[ -n "${PRIMARY_EMAIL}" ]] || die "--email is required for single mode"
  [[ -n "${FIRST_NAME}" ]] || die "--first is required for single mode"
  [[ -n "${LAST_NAME}" ]] || die "--last is required for single mode"
  [[ -n "${OU_PATH}" ]] || die "--ou is required for single mode"
  [[ -n "${PERSONAL_EMAIL}" ]] || die "--personal is required for single mode"

  process_one_user "${DIR_TOKEN}" "${PRIMARY_EMAIL}" "${FIRST_NAME}" "${LAST_NAME}" "${OU_PATH}" "${PERSONAL_EMAIL}"
  echo "[$(ts)] Done. CSV updated: ${OUT_CSV}"
  exit 0
fi

if [[ "${MODE}" == "csv" ]]; then
  [[ -n "${IN_CSV}" ]] || die "--csv path is required"
  [[ -f "${IN_CSV}" ]] || die "Input CSV not found: ${IN_CSV}"

  echo "[$(ts)] Reading input CSV: ${IN_CSV}"

  header="$(head -n 1 "${IN_CSV}" | tr -d '\r')"
  expected="primary_email,first_name,last_name,org_unit,personal_email"
  [[ "${header}" == "${expected}" ]] || die "Input CSV header must be exactly: ${expected}"

  tail -n +2 "${IN_CSV}" | while IFS=',' read -r c_email c_first c_last c_ou c_personal; do
    [[ -n "$(printf '%s' "${c_email}${c_first}${c_last}${c_ou}${c_personal}" | tr -d '[:space:]')" ]] || continue
    process_one_user "${DIR_TOKEN}" "${c_email}" "${c_first}" "${c_last}" "${c_ou}" "${c_personal}"
  done

  echo "[$(ts)] Done. CSV updated: ${OUT_CSV}"
  exit 0
fi

usage
die "You must provide either single user args (--email --first --last --ou --personal) OR --csv input.csv"