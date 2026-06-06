variable "do_token" {
  type        = string
  sensitive   = true
  description = "DigitalOcean API token, scoped to a DEDICATED lab project (PLAN.md §8.2)."
}

variable "region" {
  type        = string
  default     = "ams3"
  description = "DO region (keep the runner droplet, cluster, and registry co-located)."
}

variable "cluster_name" {
  type    = string
  default = "vulnbank-lab"
}

variable "lab_tag" {
  type        = string
  default     = "vulnbank-lab"
  description = "Tag applied to every lab resource — used by the firewall and the teardown reaper."
}

variable "k8s_version_prefix" {
  type        = string
  default     = "1.34."
  description = "DOKS version prefix; the latest matching patch is selected. (doctl kubernetes options versions)"
}

variable "node_size" {
  type    = string
  default = "s-2vcpu-4gb" # ~$24/mo each
}

variable "node_count" {
  type    = number
  default = 2
}

variable "allowed_source_cidrs" {
  type        = list(string)
  description = "Operator + CI/runner egress CIDRs allowed to reach the lab. NO default — must be set. NEVER 0.0.0.0/0."
  validation {
    condition     = length(var.allowed_source_cidrs) > 0 && !contains(var.allowed_source_cidrs, "0.0.0.0/0")
    error_message = "Refusing to expose an intentionally-vulnerable bank to the whole internet. Set explicit /32s."
  }
}

variable "docr_name" {
  type        = string
  default     = "smithbench"
  description = "DOCR registry name (globally unique, one per DO account)."
}

variable "docr_tier" {
  type        = string
  default     = "basic" # Starter (free) caps at 500 MiB/1 repo; the lab image exceeds it (PLAN.md §8.4)
  description = "DOCR subscription tier: starter | basic | professional."
}

variable "ha_control_plane" {
  type        = bool
  default     = false # HA adds +$40/mo — keep off for a lab (PLAN.md §8.2)
}
