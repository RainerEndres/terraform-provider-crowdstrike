terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}

resource "crowdstrike_recon_rule" "example" {
  name        = "example-recon-rule"
  topic       = "SA_DOMAIN"
  filter      = "example.com"
  priority    = "high"
  permissions = "private"

  breach_monitoring_enabled = true
}

output "recon_rule" {
  value = crowdstrike_recon_rule.example
}
