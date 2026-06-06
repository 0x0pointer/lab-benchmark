terraform {
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.43" }
  }
}

# DigitalOcean Container Registry. One registry per account; if you already have one,
# import it: `terraform import module.docr.digitalocean_container_registry.this <name>`.
resource "digitalocean_container_registry" "this" {
  name                   = var.registry_name
  subscription_tier_slug = var.tier
}
