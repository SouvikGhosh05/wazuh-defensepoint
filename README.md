# Wazuh SIEM on AWS - DefensePoint Assessment

A production-ready, security-focused deployment of Wazuh Security Information and Event Management (SIEM) platform on AWS using Terraform infrastructure as code.

## 🎯 **Current Status: OPERATIONAL**

- ✅ **Secure Architecture**: EC2 in private subnet, ALB in public subnet
- ✅ **Zero Public Access**: Instance accessible only via AWS SSM Session Manager
- ✅ **Production Infrastructure**: Multi-AZ deployment with NAT Gateway
- ✅ **Automated Deployment**: Complete infrastructure provisioning via Terraform
- ✅ **Battle-tested Configuration**: HTTP-based deployment with proven container compatibility

## 📁 **Project Structure**

```
wazuh-defensepoint/
├── assessment/
│   ├── docker/
│   │   └── docker-compose.yml       # Container orchestration
│   ├── scripts/
│   │   └── setup.sh                # EC2 initialization script
│   └── terraform/
│       ├── main.tf                 # Complete infrastructure definition
│       ├── outputs.tf              # Infrastructure outputs
│       ├── provider.tf             # AWS provider configuration
│       ├── terraform.tfvars        # Environment-specific variables
│       └── variables.tf            # Variable definitions
├── .gitignore
└── README.md                       # This file
```

## 🏗️ **Infrastructure Architecture**

### **Network Architecture**
- **VPC**: Custom VPC with DNS hostnames enabled
- **Multi-AZ Deployment**: Resources distributed across 2 availability zones
- **Public Subnets**: Host Application Load Balancer for internet access
- **Private Subnets**: Host EC2 instance with no direct internet access
- **NAT Gateway**: Provides outbound internet access for private subnet
- **Internet Gateway**: Enables internet access for public subnet

### **Security Architecture**
- **Private EC2 Placement**: Wazuh server deployed in private subnet
- **SSM-Only Access**: No SSH key pairs or public IPs - access via AWS Systems Manager
- **Security Groups**: Restrictive rules - ALB can only reach EC2 on port 80
- **IAM Roles**: Least privilege access with CloudWatch and SSM permissions
- **Encrypted Storage**: EBS volumes encrypted at rest

### **Application Architecture**
- **Application Load Balancer**: Internet-facing, distributes traffic to private EC2
- **Target Group**: Health check configuration for `/health` endpoint
- **Docker Containers**: Elasticsearch, Wazuh Manager, Wazuh Dashboard, Nginx proxy
- **Service Discovery**: Internal container networking with fixed IP addresses

## 🚀 **Terraform Deployment**

### **Prerequisites**
- AWS CLI configured with appropriate permissions
- Terraform >= 1.0 installed
- Access to deploy VPC, EC2, ALB, IAM resources

### **Infrastructure Components**

#### **VPC and Networking**
Terraform creates a complete network infrastructure:
- Custom VPC with configurable CIDR blocks
- Public and private subnets across multiple AZs
- Internet Gateway for public subnet connectivity
- NAT Gateway for private subnet outbound access
- Route tables and associations for proper traffic flow

#### **Security Configuration**
- **ALB Security Group**: Allows HTTP (port 80) from internet
- **EC2 Security Group**: Allows HTTP only from ALB security group
- **IAM Role**: Includes SSM Session Manager and CloudWatch permissions
- **Instance Profile**: Attached to EC2 for service access

#### **Compute Resources**
- **EC2 Instance**: Deployed in private subnet with no public IP
- **Auto-configured**: User data script handles complete Wazuh setup
- **Monitoring**: CloudWatch agent automatically installed and configured
- **Storage**: Encrypted EBS root volume with configurable size

#### **Load Balancing**
- **Application Load Balancer**: Deployed across public subnets
- **Target Group**: Health checks validate `/health` endpoint
- **HTTP Listener**: Routes traffic to private EC2 instance
- **Health Monitoring**: Automatic failover capabilities

## 🔧 **Configuration Management**

### **Terraform Variables**
The deployment is customized through `terraform/terraform.tfvars`:
- **instance_type**: EC2 instance size (minimum t3.large recommended)
- **vpc_cidr**: VPC network CIDR block
- **public_subnet_cidrs**: Public subnet CIDR blocks
- **private_subnet_cidrs**: Private subnet CIDR blocks
- **project_name**: Resource naming prefix
- **region**: AWS deployment region

### **Automated Setup**
The Terraform deployment handles:
- Complete AWS infrastructure provisioning
- Security group and IAM role creation
- EC2 instance deployment with user data script
- Docker container orchestration setup
- CloudWatch logging configuration
- Application Load Balancer configuration

### **Container Orchestration**
Docker Compose configuration includes:
- **Elasticsearch 7.17.15**: Data storage and search engine
- **Wazuh Manager 4.8.0**: Security analysis and API server
- **Wazuh Dashboard 4.8.0**: Web-based user interface
- **Nginx Proxy**: Load balancer integration and health checks

## 🔒 **Security Implementation**

### **Network Security**
- **Zero Public Exposure**: EC2 instance has no public IP address
- **Private Subnet Isolation**: Instance cannot be reached directly from internet
- **Security Group Restrictions**: Only ALB can communicate with EC2
- **NAT Gateway**: Controlled outbound internet access for updates

### **Access Control**
- **SSM Session Manager**: Secure shell access without SSH keys
- **IAM Role-based Access**: Least privilege principles
- **No Key Pairs**: Eliminates SSH key management complexity
- **CloudWatch Integration**: Comprehensive logging and monitoring

### **Data Protection**
- **Encryption at Rest**: EBS volumes encrypted
- **VPC Isolation**: Complete network isolation
- **Private Container Network**: Internal service communication

## 📊 **Service Management**

### **Access Methods**
- **Web Interface**: Access via ALB DNS name (HTTP)
- **Administrative Access**: AWS SSM Session Manager only
- **Health Monitoring**: ALB health checks and CloudWatch metrics

### **Monitoring and Logging**
- **CloudWatch Logs**: Centralized log aggregation
- **CloudWatch Metrics**: System performance monitoring
- **ALB Access Logs**: Traffic pattern analysis
- **Container Logs**: Application-level logging

### **Service Discovery**
- **Internal DNS**: Container-to-container communication
- **Fixed IP Assignment**: Predictable service addressing
- **Health Checks**: Automatic service health validation

## 🎯 **Production Features**

### **High Availability**
- **Multi-AZ Deployment**: Infrastructure spanning multiple zones
- **Load Balancer**: Automatic traffic distribution
- **Auto-recovery**: Service restart capabilities
- **Health Monitoring**: Continuous service validation

### **Scalability**
- **Vertical Scaling**: Instance type modification via Terraform
- **Storage Scaling**: EBS volume expansion capabilities
- **Container Scaling**: Resource limit adjustments
- **Network Scaling**: Subnet and IP address management

### **Security Compliance**
- **Private Network Architecture**: No direct internet access
- **Encrypted Storage**: Data protection at rest
- **Access Logging**: Comprehensive audit trail
- **Principle of Least Privilege**: Minimal required permissions

## 🔍 **Operational Management**

### **Infrastructure Management**
All infrastructure changes are managed through Terraform:
- **State Management**: Terraform state tracking
- **Change Planning**: Preview infrastructure changes
- **Rollback Capabilities**: Infrastructure version control
- **Resource Tagging**: Comprehensive resource identification

### **Application Management**
- **Container Orchestration**: Docker Compose for service management
- **Service Dependencies**: Proper startup sequencing
- **Health Validation**: Automated service health checks
- **Log Aggregation**: Centralized logging system

### **Monitoring and Alerting**
- **CloudWatch Integration**: AWS native monitoring
- **Custom Metrics**: Application-specific monitoring
- **Log Analysis**: Centralized log processing
- **Health Dashboards**: Real-time status monitoring

## 🚀 **SSL Enhancement Ready**

The infrastructure is designed for easy SSL implementation:
- **ALB SSL Termination**: Ready for HTTPS listener addition
- **Certificate Management**: AWS Certificate Manager integration
- **HTTP to HTTPS Redirect**: Simple configuration update
- **Container Compatibility**: No changes needed to working setup

## 📈 **Deployment Benefits**

### **Security Advantages**
- **Zero Attack Surface**: No public IP or SSH access
- **Network Isolation**: Complete private subnet deployment
- **Managed Access**: SSM Session Manager provides secure access
- **Compliance Ready**: Architecture supports security frameworks

### **Operational Benefits**
- **Infrastructure as Code**: Repeatable, version-controlled deployments
- **Automated Setup**: No manual configuration required
- **Monitoring Integration**: Built-in CloudWatch logging
- **Scalability**: Easy resource scaling via Terraform

### **Cost Optimization**
- **Resource Efficiency**: Right-sized instances and networking
- **Monitoring Costs**: CloudWatch integration for cost tracking
- **Automated Scaling**: Resource optimization capabilities
- **Reserved Instance Ready**: Architecture supports cost savings

## 📝 **Architecture Decisions**

### **Private Subnet Deployment**
The EC2 instance is intentionally placed in a private subnet to:
- Eliminate direct internet exposure
- Force all access through controlled ALB
- Implement defense-in-depth security
- Enable secure administrative access via SSM

### **HTTP Container Configuration**
Internal containers use HTTP to:
- Maintain proven compatibility
- Simplify certificate management
- Enable SSL termination at ALB level
- Reduce internal network complexity

### **Multi-AZ Architecture**
Resources are distributed across availability zones for:
- High availability and fault tolerance
- Load balancer resilience
- Future scaling capabilities
- Production deployment standards

---

**🎯 This Terraform-based deployment provides a secure, scalable, and production-ready Wazuh SIEM infrastructure with enterprise-grade security controls and zero public exposure.**
