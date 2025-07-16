# terraform/provider.tf - DefensePoint Assessment Provider Configuration

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region

  # Default tags applied to all resources
  default_tags {
    tags = merge(var.common_tags, {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    })
  }
}

# Configure the TLS Provider (for SSH key generation)
provider "tls" {
  # No specific configuration needed
}