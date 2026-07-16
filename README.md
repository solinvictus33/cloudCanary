# CloudCanary 🐤

**Identity drift detection for GCP — who made a key, who got a role, what changed. In your Slack within 30 minutes.**

Lightweight, agentless change-detection canary for Google Cloud. CloudCanary
sweeps your GCP org on a schedule, diffs the live resource inventory against
last-known state, and posts every delta to Slack — so your security team sees
new VMs, firewall rules, buckets, service accounts, **service-account keys**,
and **IAM privilege changes** minutes after they happen.

Built from a tool I ran in production as a first security hire: before the
org had a SIEM budget, this was the detection layer. It remains useful as a
zero-cost, zero-agent tripwire alongside (or ahead of) heavier tooling.

CloudCanary is the detection half of a pair: paved-org is the prevention half. 
The org baseline that makes the worst of these events impossible to begin with.

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
| **All-principal IAM bindings** | A human or group quietly gaining Editor/Owner |
| **Enabled APIs** | Service enablement as an early persistence/recon signal |
| **Internet-open firewall rules** | 0.0.0.0/0 ingress — posture alert, not just drift |
| **Public buckets** | `allUsers` / `allAuthenticatedUsers` grants — data exposure |
| **AI/ML API enablement** | Vertex / Gemini turned on — the AI-adoption precursor to every other AI risk |
| **`aiplatform.*` role grants** | Agent-identity privilege (Excessive Agency, LLM06) — what the AI workloads can do |
| **Public model endpoints** | `allUsers` on a Vertex endpoint — model serving exposed beyond the org |

The last two are the point: most "cloud canaries" watch compute. CloudCanary
treats **identity as the primary attack surface**.

AI workloads are watched through that same identity lens: an AI API is an
enablement event, an `aiplatform.*` grant is a privilege event, and a public
endpoint is an exposure event. See the companion threat model in
[paved-org](https://github.com/ChrisInvictus/paved-org/blob/main/docs/threat-models/mcp-trust-boundaries.md).

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
   listing), and `roles/aiplatform.viewer` (Vertex endpoint / IAM reads). Prefer Workload Identity / attached SA on the runner over
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

## Why not Security Command Center / a CNAPP?

Use them — when you can. SCC Premium and Wiz-class platforms are the right
answer at budget. CloudCanary exists for the stages and gaps they don't cover:

- **Pre-budget:** this began as the detection layer at an org with no SIEM
  or CNAPP spend. Free, agentless, running in 30 minutes.
- **Independent failure modes:** a tripwire that doesn't share credentials,
  pipelines, or vendors with your primary tooling still fires when that
  tooling is misconfigured, unpaid, or compromised.
- **Graduation path:** when the CNAPP arrives, the canary doesn't retire —
  it becomes the thing that watches the watchers.
- **The prevention half: paved-org**
  The strongest alert is the one that never fires. paved-org
  is this repo's sister project - a GCP organization baseline as code whose
  first org policy, iam.disableServiceAccountKeyCreation, prevents the
  exact event CloudCanary most wants to detect. 
  Run both: prevention for the known, detection for the drift. 
  Guardrails stop what you've predicted;
  the canary catches what you haven't.


## Limitations (honest ones)

- Polling, not event-driven: detection latency = schedule interval. For
  real-time, pair with Cloud Asset Inventory feeds / Audit Log sinks; keep
  CloudCanary as the independent tripwire that doesn't share their failure
  modes.
- Name-level diffing: renames appear as delete+create.
- State lives on the runner: pin the job to one agent or move state to a
  bucket.

## Deploy it your way

- **Jenkins** — `Jenkinsfile` included (30-minute cron, credential-bound webhook)
- **GitHub Actions** — `.github/workflows/canary.yml`, keyless auth via Workload
  Identity Federation (OIDC), state persisted via cache
- **Terraform** — `terraform/` provisions the canary's own identity as a
  secure-by-default blueprint: dedicated read-only service account, org-level
  viewer roles only, optional WIF binding so **no key is ever exported**.
  A detection tool should never depend on the credential type it exists to detect.

CI runs shellcheck on every push (`.github/workflows/lint.yml`).

## License

MIT
