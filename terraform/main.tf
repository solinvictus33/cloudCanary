# CloudCanary identity — secure-by-default blueprint.
# Creates a read-only service account for the canary and (optionally) a
# Workload Identity Federation binding so the runner authenticates without
# any exported key. A detection tool should never depend on the credential
# type it exists to detect.

variable "project_id"  { type = string }
variable "org_id"      { type = string }
variable "wif_pool"    { type = string, default = "" } # e.g. principalSet://iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/ci/attribute.repository/yourorg/cloudcanary

resource "google_service_account" "canary" {
  project      = var.project_id
  account_id   = "cloudcanary"
  display_name = "CloudCanary read-only drift detector"
}

locals {
  canary_roles = [
    "roles/browser",              # project enumeration
    "roles/compute.viewer",       # instances, firewall rules, addresses
    "roles/iam.securityReviewer", # SA, key, and IAM policy visibility
    "roles/storage.objectViewer", # bucket listing
  ]
}

resource "google_organization_iam_member" "canary" {
  for_each = toset(local.canary_roles)
  org_id   = var.org_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.canary.email}"
}

# Keyless auth from CI (recommended). If unset, attach the SA to the runner.
resource "google_service_account_iam_member" "wif" {
  count              = var.wif_pool == "" ? 0 : 1
  service_account_id = google_service_account.canary.name
  role               = "roles/iam.workloadIdentityUser"
  member             = var.wif_pool
}

output "canary_service_account" { value = google_service_account.canary.email }
