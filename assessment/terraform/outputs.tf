# terraform/outputs.tf - DefensePoint Assessment Outputs

# ============================================================================
# VPC AND NETWORK OUTPUTS
# ============================================================================

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_id" {
  description = "ID of the NAT Gateway"
  value       = aws_nat_gateway.main.id
}

output "nat_gateway_public_ip" {
  description = "Public IP of the NAT Gateway"
  value       = aws_eip.nat.public_ip
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

# ============================================================================
# EC2 INSTANCE OUTPUTS
# ============================================================================

output "instance_id" {
  description = "ID of the Wazuh EC2 instance"
  value       = aws_instance.wazuh_server.id
}

output "instance_private_ip" {
  description = "Private IP address of the Wazuh instance"
  value       = aws_instance.wazuh_server.private_ip
}

output "instance_type" {
  description = "Instance type of the Wazuh server"
  value       = aws_instance.wazuh_server.instance_type
}

output "availability_zone" {
  description = "Availability zone of the Wazuh instance"
  value       = aws_instance.wazuh_server.availability_zone
}

output "key_pair_name" {
  description = "Name of the SSH key pair"
  value       = aws_key_pair.wazuh_key.key_name
}

# ============================================================================
# SECURITY GROUP OUTPUTS
# ============================================================================

output "wazuh_security_group_id" {
  description = "ID of the Wazuh security group"
  value       = aws_security_group.wazuh_server.id
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb_sg.id
}

# ============================================================================
# ALB OUTPUTS
# ============================================================================

output "alb_dns_name" {
  description = "DNS name of the ALB"
  value       = aws_lb.wazuh_alb.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the ALB"
  value       = aws_lb.wazuh_alb.zone_id
}

output "alb_arn" {
  description = "ARN of the ALB"
  value       = aws_lb.wazuh_alb.arn
}

output "target_group_arn" {
  description = "ARN of the ALB target group"
  value       = aws_lb_target_group.wazuh_tg.arn
}

output "target_group_name" {
  description = "Name of the ALB target group"
  value       = aws_lb_target_group.wazuh_tg.name
}

# ============================================================================
# ACCESS INFORMATION
# ============================================================================

output "wazuh_dashboard_url" {
  description = "Wazuh Dashboard URL"
  value       = "http://${aws_lb.wazuh_alb.dns_name}"
}

output "wazuh_dashboard_credentials" {
  description = "Wazuh Dashboard login credentials"
  value = {
    username = "admin"
    password = var.wazuh_indexer_password
  }
  sensitive = true
}

output "health_check_url" {
  description = "ALB health check URL"
  value       = "http://${aws_lb.wazuh_alb.dns_name}/health"
}

# ============================================================================
# SSM AND LOGGING
# ============================================================================

output "ssm_session_command" {
  description = "Command to start SSM session with the Wazuh instance"
  value       = "aws ssm start-session --target ${aws_instance.wazuh_server.id} --region ${var.aws_region}"
}

output "ssm_interactive_command" {
  description = "Command to start interactive SSM session"
  value       = "aws ssm start-session --target ${aws_instance.wazuh_server.id} --region ${var.aws_region} --document-name AWS-StartInteractiveCommand --parameters 'command=[\"bash\"]'"
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name for Wazuh setup logs"
  value       = aws_cloudwatch_log_group.wazuh_logs.name
}

output "cloudwatch_log_stream_url" {
  description = "CloudWatch log stream URL"
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#logsV2:log-groups/log-group/${replace(aws_cloudwatch_log_group.wazuh_logs.name, "/", "$252F")}"
}

# ============================================================================
# IAM RESOURCES
# ============================================================================

output "iam_role_arn" {
  description = "ARN of the Wazuh EC2 IAM role"
  value       = aws_iam_role.wazuh_ec2_role.arn
}

output "iam_instance_profile_arn" {
  description = "ARN of the Wazuh EC2 instance profile"
  value       = aws_iam_instance_profile.wazuh_profile.arn
}

# ============================================================================
# CONNECTION INFO SUMMARY
# ============================================================================

output "connection_summary" {
  description = "Complete connection information for Wazuh deployment"
  value = {
    dashboard_url     = "http://${aws_lb.wazuh_alb.dns_name}"
    health_check_url  = "http://${aws_lb.wazuh_alb.dns_name}/health"
    username          = "admin"
    password          = var.wazuh_indexer_password
    instance_id       = aws_instance.wazuh_server.id
    ssm_command       = "aws ssm start-session --target ${aws_instance.wazuh_server.id} --region ${var.aws_region}"
    log_group         = aws_cloudwatch_log_group.wazuh_logs.name
    setup_log_command = "aws logs tail ${aws_cloudwatch_log_group.wazuh_logs.name} --follow --region ${var.aws_region}"
  }
  sensitive = true
}

# ============================================================================
# DEPLOYMENT STATUS
# ============================================================================

output "deployment_info" {
  description = "Deployment information and next steps"
  value = {
    vpc_cidr           = var.vpc_cidr
    region             = var.aws_region
    environment        = var.environment
    wazuh_version      = var.wazuh_version
    instance_type      = var.instance_type
    availability_zones = data.aws_availability_zones.available.names
    next_steps = [
      "1. Wait for deployment to complete (10-15 minutes)",
      "2. Check health: curl ${aws_lb.wazuh_alb.dns_name}/health",
      "3. Access dashboard: http://${aws_lb.wazuh_alb.dns_name}",
      "4. Monitor setup: aws ssm start-session --target ${aws_instance.wazuh_server.id}",
      "5. Check logs: tail -f /var/log/wazuh-setup.log"
    ]
  }
}

# ============================================================================
# QUICK ACCESS INFO
# ============================================================================

output "quick_access" {
  description = "Quick access command for immediate use"
  value       = "URL: http://${aws_lb.wazuh_alb.dns_name} | Username: admin | Password: ${var.wazuh_indexer_password} | SSM: aws ssm start-session --target ${aws_instance.wazuh_server.id} --region ${var.aws_region}"
  sensitive   = true
}