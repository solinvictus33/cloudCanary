# CloudCanary 🐤

Lightweight, agentless change-detection canary for Google Cloud. CloudCanary
sweeps your GCP org on a schedule, diffs the live resource inventory against
last-known state, and posts every delta to Slack — so your security team sees
new VMs, firewall rules, buckets, service accounts, **service-account keys**,
and **IAM privilege changes** minutes after they happen.

Built from a tool I ran in production as a first security hire: before the
org had a SIEM budget, this was the detection layer. It remains useful as a
zero-cost, zero-agent tripwire alongside (or ahead of) heavier tooling.

## What it watches

| Signal | Why it matters |
|---|---|
| Project create/delete (org-wide) | Shadow infrastructure, unsanctioned environments |
| Compute instances | Cryptomining, rogue workloads |
| Firewall rules | Exposure changes, exfil paths |
| Reserved addresses | New ingress/egress surface |
| GCS buckets | Data-exposure surface |
| Service accounts | New identities entering the estate |
| **User-managed SA keys** | Long-lived credential creation — top GCP compromise vector |
| **Per-SA IAM role bindings** | Privilege escalation / drift, per identity |

The last two are the point: most "cloud canaries" watch compute. CloudCanary
treats **identity as the primary attack surface**.

## How it works

```
Jenkins (every 30 min)
  └── cloudcanary.sh
        ├── gcloud enumerates projects → resources → identities
        ├── diff vs. state dir (last-known inventory)
        └── deltas → Slack webhook (security channel)
```

Stateless-by-design except for a plain-text state directory — no database,
no agents, no cloud-side footprint beyond read-only API calls.

## Setup

1. **Identity for the canary.** Create a dedicated service account with
   read-only roles — `roles/browser`, `roles/compute.viewer`,
   `roles/iam.securityReviewer`, `roles/storage.objectViewer` (bucket
   listing). Prefer Workload Identity / attached SA on the runner over
   exported key files. (A detection tool that requires a long-lived key
   would be flagging itself.)
2. **Slack webhook.** Create an incoming webhook for your security channel
   and store it as a secret — Jenkins Secret Text credential
   `cloudcanary-slack-webhook` in the provided pipeline. It is never
   committed.
3. **Configure.** Copy `config.example.env`, adjust, or set the same
   variables in your scheduler:

   | Variable | Default | Purpose |
   |---|---|---|
   | `SLACK_WEBHOOK_URL` | *(required)* | Delta notifications |
   | `STATE_DIR` | `~/.cloudcanary/state` | Last-known inventory |
   | `PROJECT_INCLUDE_FILTER` | *(all visible)* | `gcloud --filter` scoping |
   | `PROJECT_EXCLUDE_REGEX` | *(none)* | Skip noisy/sandbox projects |
   | `WATCH_SA_KEYS` | `true` | Key-creation detection |
   | `WATCH_SA_ROLES` | `true` | Privilege-drift detection |
   | `DRY_RUN` | `false` | Log deltas without posting |

4. **Schedule it.** `Jenkinsfile` runs it every 30 minutes
   (`cron('H/30 * * * *')`) with concurrency disabled (state files are not
   concurrency-safe). Plain cron or Cloud Scheduler + Cloud Run job work the
   same way.

First run seeds state and stays quiet; drift alerts begin from run two.

## Security practices in this repo

- **No secrets in code.** Webhook injected at runtime from a credential
  store; the script refuses to start without it.
- **Injection-safe notifications.** Slack payloads built with `jq`, not
  string interpolation.
- **Least privilege.** Read-only viewer roles; nothing in the canary can
  mutate the estate.
- **Fail-loudly.** Pipeline failure posts its own alert — a dead canary is
  a detection gap, and it says so.
- **`set -euo pipefail`**, quoted expansions, and per-call error isolation
  so one flaky API doesn't silently skip a project.

## Limitations (honest ones)

- Polling, not event-driven: detection latency = schedule interval. For
  real-time, pair with Cloud Asset Inventory feeds / Audit Log sinks; keep
  CloudCanary as the independent tripwire that doesn't share their failure
  modes.
- Name-level diffing: renames appear as delete+create.
- State lives on the runner: pin the job to one agent or move state to a
  bucket.

## License

MIT
