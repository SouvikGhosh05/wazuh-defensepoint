# terraform/variables.tf - DefensePoint Assessment Variables

# ============================================================================
# AWS CONFIGURATION
# ============================================================================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "ap-south-1"
}

# ============================================================================
# PROJECT CONFIGURATION
# ============================================================================

variable "project_name" {
  description = "Name of the project used for resource naming"
  type        = string
  default     = "defensepoint-wazuh"
}

variable "environment" {
  description = "Environment name (dev, staging, prod, assessment)"
  type        = string
  default     = "assessment"
}

variable "wazuh_dir" {
  description = "Directory to install Wazuh Docker setup on the EC2 instance"
  type        = string
  default     = "/opt/wazuh-docker"
}

# ============================================================================
# NETWORK CONFIGURATION - 2 AZs as per requirements
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets across 2 AZs"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets across 2 AZs"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

# ============================================================================
# EC2 CONFIGURATION - t3.xlarge as per requirements
# ============================================================================

variable "instance_type" {
  description = "EC2 instance type for Wazuh server (minimum t3.xlarge recommended)"
  type        = string
  default     = "t3.xlarge"
}

variable "root_volume_size" {
  description = "Size of the root EBS volume in GB"
  type        = number
  default     = 50
}

variable "root_volume_type" {
  description = "Type of the root EBS volume"
  type        = string
  default     = "gp3"
}

# ============================================================================
# WAZUH CONFIGURATION
# ============================================================================

variable "wazuh_version" {
  description = "Wazuh version to deploy"
  type        = string
  default     = "4.8.0"
}

variable "wazuh_indexer_password" {
  description = "Password for Wazuh indexer admin user"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.wazuh_indexer_password) >= 8
    error_message = "Wazuh indexer password must be at least 8 characters long."
  }
}

variable "wazuh_api_password" {
  description = "Password for Wazuh API user"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.wazuh_api_password) >= 8
    error_message = "Wazuh API password must be at least 8 characters long."
  }
}

variable "wazuh_dashboard_password" {
  description = "Password for Wazuh dashboard user"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.wazuh_dashboard_password) >= 8
    error_message = "Wazuh dashboard password must be at least 8 characters long."
  }
}

# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

variable "wazuh_ingress_rules" {
  description = "Ingress rules for Wazuh security group - essential ports only"
  type = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
  }))
  default = [
    {
      description = "Wazuh Dashboard HTTP (via ALB)"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
    },
    {
      description = "Wazuh Dashboard HTTPS (via ALB)"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
    }
  ]
}

variable "enable_termination_protection" {
  description = "Enable EC2 termination protection"
  type        = bool
  default     = false
}

# ============================================================================
# MONITORING CONFIGURATION
# ============================================================================

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 60
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring for EC2 (additional cost)"
  type        = bool
  default     = false
}

# ============================================================================
# BACKUP CONFIGURATION
# ============================================================================

variable "enable_backup" {
  description = "Enable automated backups for EC2 instance"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain automated backups"
  type        = number
  default     = 7
}

# ============================================================================
# TAGGING
# ============================================================================

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "DefensePoint-Wazuh"
    Environment = "Assessment"
    Terraform   = "true"
    CreatedBy   = "Terraform"
  }
}

# ============================================================================
# ADVANCED CONFIGURATION (Optional)
# ============================================================================

variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs for network monitoring"
  type        = bool
  default     = false
}

variable "enable_ssm_patch_manager" {
  description = "Enable SSM Patch Manager for automatic patching"
  type        = bool
  default     = true
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access Wazuh dashboard (empty means all)"
  type        = list(string)
  default     = []
}

variable "enable_enhanced_security" {
  description = "Enable enhanced security features (stricter security groups, etc.)"
  type        = bool
  default     = true
}