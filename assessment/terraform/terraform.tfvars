# terraform.tfvars - DefensePoint Assessment Configuration

# ============================================================================
# AWS CONFIGURATION
# ============================================================================
aws_region = "ap-south-1"  # Mumbai region as per assessment requirements

# ============================================================================
# PROJECT CONFIGURATION
# ============================================================================
project_name = "defensepoint-wazuh"
environment  = "assessment"
wazuh_dir    = "/opt/wazuh-docker"

# ============================================================================
# NETWORK CONFIGURATION - 2 AZs as per requirements
# ============================================================================
vpc_cidr = "10.0.0.0/16"

# Public subnets across 2 availability zones
public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]

# Private subnets across 2 availability zones  
private_subnet_cidrs = ["10.0.11.0/24", "10.0.12.0/24"]

# ============================================================================
# EC2 CONFIGURATION - t3.xlarge as per requirements
# ============================================================================
instance_type    = "t3.xlarge"  # Required by assessment - minimum for Wazuh
root_volume_size = 50           # GB - sufficient for Wazuh deployment
root_volume_type = "gp3"        # Modern volume type for better performance

# ============================================================================
# WAZUH CONFIGURATION
# ============================================================================
wazuh_version = "4.8.0"

# Security passwords - IMPORTANT: Change these for production!
# These passwords meet the validation requirements (8+ chars, upper, lower, number)
wazuh_indexer_password   = "DefensePoint2024!Indexer"
wazuh_api_password       = "DefensePoint2024!API"
wazuh_dashboard_password = "DefensePoint2024!Dashboard"

# ============================================================================
# SECURITY CONFIGURATION - Essential ports only for assessment
# ============================================================================
wazuh_ingress_rules = [
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

enable_termination_protection = false  # Assessment environment - disable for easy cleanup

# ============================================================================
# MONITORING CONFIGURATION
# ============================================================================
log_retention_days         = 60    # 2 months for assessment
enable_detailed_monitoring = false # Basic monitoring sufficient for assessment

# ============================================================================
# BACKUP CONFIGURATION
# ============================================================================
enable_backup         = true  # Enable for data protection
backup_retention_days = 7     # Weekly retention for assessment

# ============================================================================
# ADVANCED CONFIGURATION
# ============================================================================
enable_vpc_flow_logs      = false  # Disable to reduce costs for assessment
enable_ssm_patch_manager  = true   # Enable for security updates
enable_enhanced_security  = true   # Enable enhanced security features

# Optional: Restrict access to specific CIDR blocks
# allowed_cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]  # Replace with your actual IP ranges
allowed_cidr_blocks = []  # Empty = allow all (for assessment only)

# ============================================================================
# RESOURCE TAGS
# ============================================================================
common_tags = {
  Owner         = "SecurityTeam"
  Environment   = "Assessment"
  Assessment    = "DefensePoint"
  Region        = "Mumbai"
  Project       = "Wazuh-SIEM"
  Department    = "Security"
  CostCenter    = "IT-Security"
  Terraform     = "true"
  CreatedBy     = "Terraform"
  Purpose       = "Security-Monitoring"
  Compliance    = "SOC2"
  DataClass     = "Internal"
  Backup        = "Enabled"
  Monitoring    = "CloudWatch"
}