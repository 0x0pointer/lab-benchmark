terraform {
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.43" }
  }
}

resource "digitalocean_kubernetes_cluster" "this" {
  name         = var.cluster_name
  region       = var.region
  version      = var.k8s_version
  vpc_uuid     = var.vpc_uuid
  ha           = var.ha_control_plane
  auto_upgrade = false

  # CRITICAL (PLAN.md risk #12): destroy orphaned LBs/volumes created by the K8s API
  # so `terraform destroy` actually returns the account to $0.
  destroy_all_associated_resources = true

  tags = [var.lab_tag]

  node_pool {
    name       = "${var.cluster_name}-pool"
    size       = var.node_size
    node_count = var.node_count
    # Tag the nodes so the tag-targeted firewall (and the teardown reaper) find them.
    tags = [var.lab_tag]
  }
}
