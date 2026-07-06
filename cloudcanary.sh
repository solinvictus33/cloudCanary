#!/usr/bin/env bash
#
# CloudCanary — lightweight GCP change-detection canary
#
# Detects creation/deletion drift across GCP resources and posts deltas
# to a Slack channel. Designed to run on a schedule (Jenkins, cron, or
# Cloud Scheduler + Cloud Run job).
#
# Resources watched:
#   - Projects (org-wide additions/removals)
#   - Compute instances
#   - Firewall rules
#   - Reserved addresses
#   - GCS buckets
#   - Service accounts
#   - Service account keys (user-managed)   <- identity-governance signal
#   - Per-service-account IAM role bindings <- privilege-drift signal
#
# Configuration is environment-driven. No secrets in this file. See
# config.example.env and README.md.

set -euo pipefail

# ------------------------------------------------------------------ config
: "${SLACK_WEBHOOK_URL:?SLACK_WEBHOOK_URL is required (inject via CI credential store, never hardcode)}"
STATE_DIR="${STATE_DIR:-${HOME}/.cloudcanary/state}"
PROJECT_INCLUDE_FILTER="${PROJECT_INCLUDE_FILTER:-}"   # optional gcloud --filter expression
PROJECT_EXCLUDE_REGEX="${PROJECT_EXCLUDE_REGEX:-}"     # optional grep -Ev pattern
WATCH_SA_KEYS="${WATCH_SA_KEYS:-true}"
WATCH_SA_ROLES="${WATCH_SA_ROLES:-true}"
WATCH_IAM_MEMBERS="${WATCH_IAM_MEMBERS:-true}"         # project-level role grants to ANY principal
WATCH_ENABLED_APIS="${WATCH_ENABLED_APIS:-true}"       # service/API enablement drift
WATCH_PUBLIC_EXPOSURE="${WATCH_PUBLIC_EXPOSURE:-true}" # 0.0.0.0/0 firewall + public buckets
DRY_RUN="${DRY_RUN:-false}"                            # true = log only, no Slack posts

mkdir -p "${STATE_DIR}"

# ------------------------------------------------------------------ helpers
log() { printf '%s [cloudcanary] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

notify() {
  # Posts a message to Slack. Payload built with jq to stay injection-safe.
  local text="$1"
  if [[ "${DRY_RUN}" == "true" ]]; then
    log "DRY_RUN notify: ${text}"
    return 0
  fi
  jq -n --arg text "${text}" '{text: $text}' \
    | curl -fsS -X POST -H 'Content-type: application/json' \
        --data @- "${SLACK_WEBHOOK_URL}" >/dev/null \
    || log "WARN: Slack notification failed"
}

# diff_and_alert <state-file-basename> <label> <current-list>
# Compares the current listing against last-known state; alerts on delta;
# rotates state only after a successful comparison.
diff_and_alert() {
  local state_file="${STATE_DIR}/$1"
  local label="$2"
  local current="$3"

  touch "${state_file}"
  local previous
  previous="$(cat "${state_file}")"

  if [[ "${current}" == "${previous}" ]]; then
    return 0
  fi

  local delta
  delta="$(printf '%s\n%s\n' "${previous}" "${current}" | sort | uniq -u | sed '/^$/d')"

  if [[ -n "${delta}" ]]; then
    log "DRIFT: ${label}"
    notify ":rotating_light: *CloudCanary* — change detected: ${label}
\`\`\`
${delta}
\`\`\`"
  fi

  printf '%s\n' "${current}" > "${state_file}"
}

gcloud_list() {
  # Wrapper so a single API hiccup doesn't kill the whole run.
  "$@" 2>/dev/null || { log "WARN: command failed: $*"; echo ""; }
}

# ------------------------------------------------------------------ projects
log "Enumerating projects"
PROJECTS="$(gcloud_list gcloud projects list \
  ${PROJECT_INCLUDE_FILTER:+--filter="${PROJECT_INCLUDE_FILTER}"} \
  --format='value(projectId)')"

if [[ -n "${PROJECT_EXCLUDE_REGEX}" ]]; then
  PROJECTS="$(printf '%s\n' "${PROJECTS}" | grep -Ev "${PROJECT_EXCLUDE_REGEX}" || true)"
fi

diff_and_alert "projects.list" "GCP project created/deleted (org-wide)" "${PROJECTS}"

# ------------------------------------------------------------------ per-project sweep
while IFS= read -r project; do
  [[ -z "${project}" ]] && continue
  log "Scanning project: ${project}"

  diff_and_alert "${project}.instances" \
    "Compute instance(s) in \`${project}\`" \
    "$(gcloud_list gcloud compute instances list --project "${project}" --format='value(name)')"

  diff_and_alert "${project}.firewall" \
    "Firewall rule(s) in \`${project}\`" \
    "$(gcloud_list gcloud compute firewall-rules list --project "${project}" --format='value(name)')"

  diff_and_alert "${project}.addresses" \
    "Reserved address(es) in \`${project}\`" \
    "$(gcloud_list gcloud compute addresses list --project "${project}" --format='value(name)')"

  diff_and_alert "${project}.buckets" \
    "GCS bucket(s) in \`${project}\`" \
    "$(gcloud_list gcloud storage ls --project "${project}")"

  SERVICE_ACCOUNTS="$(gcloud_list gcloud iam service-accounts list --project "${project}" --format='value(email)')"
  diff_and_alert "${project}.service-accounts" \
    "Service account(s) in \`${project}\`" \
    "${SERVICE_ACCOUNTS}"

  if [[ "${WATCH_IAM_MEMBERS}" == "true" ]]; then
    # Full role->member map: catches a human or group gaining Editor/Owner,
    # not just service-account drift.
    diff_and_alert "${project}.iam-bindings" \
      "IAM role binding(s) in \`${project}\` (any principal — check for primitive roles)" \
      "$(gcloud_list gcloud projects get-iam-policy "${project}" \
           --flatten='bindings[].members' \
           --format='value(bindings.role,bindings.members)')"
  fi

  if [[ "${WATCH_ENABLED_APIS}" == "true" ]]; then
    # New API enablement is an early persistence/recon signal.
    diff_and_alert "${project}.enabled-apis" \
      "Enabled API(s) in \`${project}\`" \
      "$(gcloud_list gcloud services list --enabled --project "${project}" --format='value(config.name)')"
  fi

  if [[ "${WATCH_PUBLIC_EXPOSURE}" == "true" ]]; then
    # Posture, not just drift: ingress open to the internet.
    diff_and_alert "${project}.public-firewall" \
      ":rotating_light: INTERNET-OPEN firewall rule(s) in \`${project}\` (0.0.0.0/0 ingress)" \
      "$(gcloud_list gcloud compute firewall-rules list --project "${project}" \
           --filter='direction=INGRESS AND disabled=false' \
           --format='value(name,sourceRanges.list())' | grep '0\.0\.0\.0/0' || true)"

    # Buckets granting allUsers / allAuthenticatedUsers = public data surface.
    PUBLIC_BUCKETS=""
    while IFS= read -r bucket; do
      [[ -z "${bucket}" ]] && continue
      if gcloud_list gcloud storage buckets get-iam-policy "${bucket}" --format=json \
           | grep -qE '"allUsers"|"allAuthenticatedUsers"'; then
        PUBLIC_BUCKETS+="${bucket}"$'\n'
      fi
    done <<< "$(gcloud_list gcloud storage buckets list --project "${project}" --format='value(storage_url)')"
    diff_and_alert "${project}.public-buckets" \
      ":rotating_light: PUBLIC bucket(s) in \`${project}\` (allUsers/allAuthenticatedUsers)" \
      "${PUBLIC_BUCKETS}"
  fi

  # ---------------------------------------------------------------- identity governance
  while IFS= read -r sa; do
    [[ -z "${sa}" ]] && continue

    if [[ "${WATCH_SA_KEYS}" == "true" ]]; then
      diff_and_alert "${project}.${sa}.keys" \
        "User-managed key(s) for \`${sa}\` in \`${project}\` (long-lived credential event)" \
        "$(gcloud_list gcloud iam service-accounts keys list \
             --iam-account "${sa}" --managed-by user --format='value(name)')"
    fi

    if [[ "${WATCH_SA_ROLES}" == "true" ]]; then
      diff_and_alert "${project}.${sa}.roles" \
        "IAM role binding(s) for \`${sa}\` in \`${project}\` (privilege drift)" \
        "$(gcloud_list gcloud projects get-iam-policy "${project}" \
             --flatten='bindings[].members' \
             --filter="bindings.members:serviceAccount:${sa}" \
             --format='value(bindings.role)')"
    fi
  done <<< "${SERVICE_ACCOUNTS}"

done <<< "${PROJECTS}"

log "Sweep complete"
