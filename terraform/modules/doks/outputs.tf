output "cluster_id" {
  value = digitalocean_kubernetes_cluster.this.id
}

output "cluster_name" {
  value = digitalocean_kubernetes_cluster.this.name
}

output "endpoint" {
  value = digitalocean_kubernetes_cluster.this.endpoint
}

output "kubeconfig" {
  value     = digitalocean_kubernetes_cluster.this.kube_config[0].raw_config
  sensitive = true
}
