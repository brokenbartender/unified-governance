terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
    }
  }
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

resource "helm_release" "unified_governance" {
  name       = var.release_name
  namespace  = var.namespace
  chart      = var.chart_path

  set {
    name  = "image.repository"
    value = var.image_repository
  }

  set {
    name  = "image.tag"
    value = var.image_tag
  }

  set {
    name  = "env.EVIDENCE_HMAC_SECRET"
    value = var.evidence_hmac_secret
  }

  set {
    name  = "env.DB_URL"
    value = var.db_url
  }

  set {
    name  = "env.RETENTION_DAYS"
    value = var.retention_days
  }
}
