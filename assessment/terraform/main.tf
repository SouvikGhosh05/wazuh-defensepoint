# terraform/main.tf - DefensePoint Wazuh Assessment - Mumbai Region

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "zone-type"
    values = ["availability-zone"]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-*-*-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical's owner ID
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ============================================================================
# VPC INFRASTRUCTURE - 2 AZs as per requirements
# ============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Public Subnets across 2 AZs
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet-${count.index + 1}"
    Type = "Public"
    AZ   = data.aws_availability_zones.available.names[count.index]
  }
}

# Private Subnets across 2 AZs
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-private-subnet-${count.index + 1}"
    Type = "Private"
    AZ   = data.aws_availability_zones.available.names[count.index]
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-nat-eip"
  }

  depends_on = [aws_internet_gateway.main]
}

# NAT Gateway for private subnet
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.project_name}-nat-gateway"
  }

  depends_on = [aws_internet_gateway.main]
}

# Public route table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

# Private route table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

# Route table associations
resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ============================================================================
# SECURITY GROUPS - ALB to Private EC2
# ============================================================================

# ALB Security Group - Allow HTTP from Internet
resource "aws_security_group" "alb_sg" {
  name_prefix = "${var.project_name}-alb-"
  description = "Allow HTTP traffic to ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow outbound to VPC for health checks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# EC2 Security Group - Allow HTTP from ALB only
resource "aws_security_group" "wazuh_server" {
  name_prefix = "${var.project_name}-wazuh-server-"
  description = "Allow traffic only from ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow HTTP from ALB only"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-wazuh-server-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# IAM ROLES AND POLICIES - SSM Access
# ============================================================================

resource "aws_iam_role" "wazuh_ec2_role" {
  name        = "${var.project_name}-wazuh-ec2-role"
  path        = "/"
  description = "IAM role for Wazuh EC2 instance with SSM Session Manager access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2AssumeRole"
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-wazuh-ec2-role"
  }
}

resource "aws_iam_instance_profile" "wazuh_profile" {
  name = "${var.project_name}-wazuh-profile"
  path = "/"
  role = aws_iam_role.wazuh_ec2_role.name

  tags = {
    Name = "${var.project_name}-wazuh-profile"
  }
}

resource "aws_iam_role_policy" "wazuh_cloudwatch_policy" {
  name = "${var.project_name}-cloudwatch-policy"
  role = aws_iam_role.wazuh_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/${var.project_name}*",
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/${var.project_name}*:*"
        ]
      },
      {
        Sid    = "CloudWatchMetricsAccess"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "wazuh_ssm_enhanced_policy" {
  name = "${var.project_name}-ssm-enhanced-policy"
  role = aws_iam_role.wazuh_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMSessionManagerAccess"
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssm:SendCommand",
          "ssm:ListCommands",
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation",
          "ssm:GetConnectionStatus"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMMessagesForSessionManager"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2MessagesForSSM"
        Effect = "Allow"
        Action = [
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetEndpoint",
          "ec2messages:GetMessages",
          "ec2messages:SendReply"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  role       = aws_iam_role.wazuh_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_server_policy" {
  role       = aws_iam_role.wazuh_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# ============================================================================
# CLOUDWATCH LOGGING
# ============================================================================

resource "aws_cloudwatch_log_group" "wazuh_logs" {
  name              = "/aws/ec2/${var.project_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-logs"
  }
}

# ============================================================================
# EC2 INSTANCE - In Private Subnet
# ============================================================================

resource "tls_private_key" "wazuh_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "wazuh_key" {
  key_name   = "${var.project_name}-key"
  public_key = tls_private_key.wazuh_ssh.public_key_openssh
}

resource "aws_instance" "wazuh_server" {
  ami                     = data.aws_ami.ubuntu.id
  instance_type           = var.instance_type
  subnet_id               = aws_subnet.private[0].id  # PRIVATE SUBNET
  vpc_security_group_ids  = [aws_security_group.wazuh_server.id]
  iam_instance_profile    = aws_iam_instance_profile.wazuh_profile.name
  disable_api_termination = var.enable_termination_protection
  monitoring              = var.enable_detailed_monitoring
  key_name                = aws_key_pair.wazuh_key.key_name

  root_block_device {
    volume_type           = var.root_volume_type
    volume_size           = var.root_volume_size
    encrypted             = true
    delete_on_termination = true

    tags = {
      Name = "${var.project_name}-root-volume"
    }
  }

  user_data_base64 = base64gzip(templatefile("${path.module}/../scripts/setup.sh", {
    docker_compose_b64 = base64encode(file("${path.module}/../docker/docker-compose.yml"))
  }))

  tags = {
    Name   = "${var.project_name}-wazuh-server"
    Backup = var.enable_backup ? "true" : "false"
  }

  depends_on = [
    aws_cloudwatch_log_group.wazuh_logs,
    aws_nat_gateway.main,
    aws_iam_role_policy_attachment.ssm_managed_instance_core,
    aws_iam_role_policy_attachment.cloudwatch_agent_server_policy
  ]
}

# ============================================================================
# APPLICATION LOAD BALANCER - In Public Subnets
# ============================================================================

resource "aws_lb" "wazuh_alb" {
  name               = "${var.project_name}-alb"
  internal           = false  # Internet-facing
  load_balancer_type = "application"
  subnets            = aws_subnet.public[*].id  # PUBLIC SUBNETS
  security_groups    = [aws_security_group.alb_sg.id]

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# Target Group - Points to Private EC2
resource "aws_lb_target_group" "wazuh_tg" {
  name        = "${var.project_name}-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path                = "/health"  # CRITICAL: nginx health endpoint
    protocol            = "HTTP"
    port                = "80"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }

  tags = {
    Name = "${var.project_name}-tg"
  }
}

# HTTP Listener
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.wazuh_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wazuh_tg.arn
  }
}

# Attach Private EC2 to Target Group
resource "aws_lb_target_group_attachment" "wazuh_ec2_attach" {
  target_group_arn = aws_lb_target_group.wazuh_tg.arn
  target_id        = aws_instance.wazuh_server.id
  port             = 80
}