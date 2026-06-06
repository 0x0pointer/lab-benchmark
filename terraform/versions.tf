terraform {
  required_version = ">= 1.5"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.43"
    }
  }
  # Recommended: move state off local disk — it holds the DO token + kubeconfig in
  # plaintext (PLAN.md risk #20). Configure a DO Spaces (S3-compatible) backend:
  # backend "s3" {
  #   endpoints                   = { s3 = "https://<region>.digitaloceanspaces.com" }
  #   bucket                      = "my-tf-state"
  #   key                         = "vulnbank-lab/terraform.tfstate"
  #   region                      = "us-east-1"   # dummy; DO ignores
  #   skip_credentials_validation = true
  #   skip_metadata_api_check     = true
  #   skip_region_validation      = true
  #   skip_requesting_account_id  = true
  # }
}

provider "digitalocean" {
  token = var.do_token
}
