output "registry_name" {
  value = digitalocean_container_registry.this.name
}

output "endpoint" {
  value = digitalocean_container_registry.this.endpoint
}
