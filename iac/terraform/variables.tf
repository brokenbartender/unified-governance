variable "kubeconfig_path" {
  type        = string
  description = "Path to kubeconfig"
}

variable "namespace" {
  type        = string
  default     = "default"
}

variable "release_name" {
  type        = string
  default     = "unified-governance"
}

variable "chart_path" {
  type        = string
  default     = "../helm/unified-governance"
}

variable "image_repository" {
  type        = string
}

variable "image_tag" {
  type        = string
  default     = "latest"
}

variable "evidence_hmac_secret" {
  type        = string
}

variable "db_url" {
  type        = string
  default     = ""
}

variable "retention_days" {
  type        = string
  default     = "90"
}
