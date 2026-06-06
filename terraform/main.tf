# Root config: VPC + DOKS cluster + DOCR registry + a tag-targeted firewall.
#
# EXPOSURE MODEL (safety-critical — PLAN.md §8.2, risk #1):
# DO cloud firewalls are whitelist/union-only — you cannot DENY, and adding a
# restrictive firewall does NOT override a permissive one. So we do NOT rely on a
# firewall to "close" a public NodePort. Instead the SAFE DEFAULT is:
#   * cluster lives in a private VPC,
#   * the operator reaches the lab via authenticated `kubectl port-forward`
#     (emit-target.sh portforward mode) — zero public exposure, OR
#   * agent-smith runs on a same-VPC runner droplet reaching node PRIVATE IPs.
# The firewall below additionally restricts SSH/any-public to allowed_source_cidrs.
# Phase-2 acceptance MUST empirically verify a node's public IP:NodePort is NOT
# reachable from outside the allowlist (engineer it, don't assert it).

data "digitalocean_kubernetes_versions" "current" {
  version_prefix = var.k8s_version_prefix
}

resource "digitalocean_vpc" "lab" {
  name     = "${var.cluster_name}-vpc"
  region   = var.region
  ip_range = "10.111.0.0/20"
}

# NOTE: DigitalOcean allows ONE container registry per account, and this account
# already has 'foundry-registry'. We reuse it (unmanaged here so `terraform destroy`
# never deletes a shared registry). Images push to registry.digitalocean.com/<docr_name>.
# The docr module is intentionally NOT instantiated; set var.docr_name to the existing one.

module "doks" {
  source           = "./modules/doks"
  cluster_name     = var.cluster_name
  region           = var.region
  vpc_uuid         = digitalocean_vpc.lab.id
  k8s_version      = data.digitalocean_kubernetes_versions.current.latest_version
  node_size        = var.node_size
  node_count       = var.node_count
  ha_control_plane = var.ha_control_plane
  lab_tag          = var.lab_tag
}

# Tag-targeted firewall (NOT watched by the DOKS reconciler, so it is not reverted).
# Restricts the worker nodes' public surface to the operator/runner CIDRs. NodePorts
# are intended to be reached intra-VPC; this is defense-in-depth, not the only control.
resource "digitalocean_firewall" "lab_lock" {
  name = "${var.cluster_name}-lock"
  tags = [var.lab_tag]

  # Allow node-to-node within the VPC (kept permissive inside the private network).
  inbound_rule {
    protocol         = "tcp"
    port_range       = "1-65535"
    source_addresses = [digitalocean_vpc.lab.ip_range]
  }
  inbound_rule {
    protocol         = "udp"
    port_range       = "1-65535"
    source_addresses = [digitalocean_vpc.lab.ip_range]
  }

  # Any PUBLIC access (e.g. if you deliberately enable a public NodePort) is limited
  # to the operator/runner allowlist — never the whole internet.
  inbound_rule {
    protocol         = "tcp"
    port_range       = "30000-32767"
    source_addresses = var.allowed_source_cidrs
  }

  # Egress: allow all (the lab needs DNS, image pulls, optional DeepSeek on raw).
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
