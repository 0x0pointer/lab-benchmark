variable "cluster_name" { type = string }
variable "region" { type = string }
variable "vpc_uuid" { type = string }
variable "k8s_version" { type = string }
variable "node_size" { type = string }
variable "node_count" { type = number }
variable "ha_control_plane" { type = bool }
variable "lab_tag" { type = string }
