output "cluster_id" {
  value = module.doks.cluster_id
}

output "cluster_name" {
  value = module.doks.cluster_name
}

output "vpc_id" {
  value = digitalocean_vpc.lab.id
}

output "registry_endpoint" {
  value = "registry.digitalocean.com/${var.docr_name}"
}

output "kubeconfig" {
  value     = module.doks.kubeconfig
  sensitive = true
}

# Convenience: how to wire kubectl + DOCR pull secret after apply.
output "post_apply_hint" {
  value = <<-EOT
    doctl kubernetes cluster kubeconfig save ${module.doks.cluster_name}
    doctl kubernetes cluster registry add ${module.doks.cluster_name}   # injects DOCR pull secret
    make deploy-raw                                                      # kustomize apply overlays/raw
  EOT
}
