#!/bin/bash

set -euxo pipefail
exec > >(tee -a /var/log/wazuh-setup.log) 2>&1

echo "[INFO] Starting Wazuh Setup at $(date)"

# Install packages
echo "[INFO] Installing packages..."
apt-get update -y
apt-get install -y docker.io docker-compose wget curl git jq netcat

# Enable Docker
echo "[INFO] Setting up Docker..."
systemctl enable --now docker
usermod -aG docker ubuntu
sleep 10

# Setup Wazuh directory
mkdir -p /opt/wazuh-docker
cd /opt/wazuh-docker

# Decode docker-compose file
echo "[INFO] Creating docker-compose.yml..."
echo "${docker_compose_b64}" | base64 -d > docker-compose.yml

# Validate docker-compose
if ! docker-compose config >/dev/null 2>&1; then
  echo "[ERROR] Invalid docker-compose.yml"
  exit 1
fi

# Clone Wazuh config repo
echo "[INFO] Cloning Wazuh config repo..."
git clone https://github.com/wazuh/wazuh-docker.git wazuh-repo
cd wazuh-repo
git checkout v4.8.0 || true

# Copy base configs
mkdir -p /opt/wazuh-docker/config
cp -r single-node/config/* /opt/wazuh-docker/config/

# Create opensearch config directory and file
mkdir -p /opt/wazuh-docker/config/wazuh_indexer

# Create opensearch.yml configuration
cat > /opt/wazuh-docker/config/wazuh_indexer/opensearch.yml <<'EOF'
# OpenSearch configuration for Wazuh Indexer
cluster.name: wazuh-cluster
node.name: wazuh.indexer
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

# Path settings
path.data: /usr/share/wazuh-indexer/data
path.logs: /usr/share/wazuh-indexer/logs

# SSL/TLS Configuration
plugins.security.ssl.transport.pemcert_filepath: certs/esnode.pem
plugins.security.ssl.transport.pemkey_filepath: certs/esnode-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/esnode.pem
plugins.security.ssl.http.pemkey_filepath: certs/esnode-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem

# Security Configuration
plugins.security.authcz.admin_dn:
  - CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US

plugins.security.nodes_dn:
  - CN=wazuh.indexer,OU=Wazuh,O=Wazuh,L=California,C=US

plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices:
  - ".opendistro-alerting-config"
  - ".opendistro-alerting-alert*"
  - ".opendistro-anomaly-results*"
  - ".opendistro-anomaly-detector*"
  - ".opendistro-anomaly-checkpoints"
  - ".opendistro-anomaly-detection-state"
  - ".opendistro-reports-*"
  - ".opendistro-notifications-*"
  - ".opendistro-notebooks"
  - ".opendistro-asynchronous-search-response*"

# Performance settings
bootstrap.memory_lock: true
indices.query.bool.max_clause_count: 8192
search.max_buckets: 250000

# Compatibility settings
compatibility.override_main_response_version: true
EOF

echo "[INFO] Created OpenSearch configuration"

# Remove demo certs - we'll generate proper ones
rm -rf /opt/wazuh-docker/config/wazuh_indexer_ssl_certs
cd /opt/wazuh-docker

# Create data directories with proper permissions
mkdir -p data/{wazuh-indexer-data,wazuh_logs,wazuh_etc,wazuh_queue,wazuh_var_multigroups,wazuh_integrations,wazuh_active_response,wazuh_agentless,wazuh_wodles,filebeat_etc,filebeat_var,wazuh_api_configuration,wazuh_dashboard_config,wazuh_dashboard_custom}
chown -R 1000:1000 data/

# Create certificate directory
mkdir -p certs
cd certs

# Download cert tool
wget https://packages.wazuh.com/4.8/wazuh-certs-tool.sh
chmod +x wazuh-certs-tool.sh

# Generate cert config with proper hostnames and static IPs
cat > config.yml <<EOF
nodes:
  indexer:
    - name: wazuh.indexer
      ip: 172.20.0.2
  server:
    - name: wazuh.manager
      ip: 172.20.0.3
  dashboard:
    - name: wazuh.dashboard
      ip: 172.20.0.4
EOF

# Clean previous certificates
rm -rf wazuh-certificates/

# Generate certificates with correct configuration
echo "[INFO] Generating SSL certificates..."
./wazuh-certs-tool.sh -A

# Validate certificates were generated with correct CN
if ! openssl x509 -in wazuh-certificates/wazuh.indexer.pem -text -noout | grep -q "CN.*wazuh\.indexer"; then
    echo "[ERROR] Certificate CN validation failed"
    echo "[INFO] Certificate details:"
    openssl x509 -in wazuh-certificates/wazuh.indexer.pem -text -noout | grep -A 1 "Subject:"
    exit 1
fi

echo "[INFO] Certificate validation passed"

# Create final certificate directory structure
cd /opt/wazuh-docker
mkdir -p config/wazuh_indexer_ssl_certs

# Copy certificates with proper naming for Docker volumes
cp certs/wazuh-certificates/root-ca.pem config/wazuh_indexer_ssl_certs/
cp certs/wazuh-certificates/admin.pem config/wazuh_indexer_ssl_certs/
cp certs/wazuh-certificates/admin-key.pem config/wazuh_indexer_ssl_certs/

# Indexer certificates
cp certs/wazuh-certificates/wazuh.indexer.pem config/wazuh_indexer_ssl_certs/wazuh.indexer.pem
cp certs/wazuh-certificates/wazuh.indexer-key.pem config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem
cp certs/wazuh-certificates/wazuh.indexer.pem config/wazuh_indexer_ssl_certs/esnode.pem
cp certs/wazuh-certificates/wazuh.indexer-key.pem config/wazuh_indexer_ssl_certs/esnode-key.pem

# Manager certificates (for Filebeat)
cp certs/wazuh-certificates/wazuh.manager.pem config/wazuh_indexer_ssl_certs/wazuh.manager.pem
cp certs/wazuh-certificates/wazuh.manager-key.pem config/wazuh_indexer_ssl_certs/wazuh.manager-key.pem
cp certs/wazuh-certificates/root-ca.pem config/wazuh_indexer_ssl_certs/root-ca-manager.pem

# Dashboard certificates
cp certs/wazuh-certificates/wazuh.dashboard.pem config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem
cp certs/wazuh-certificates/wazuh.dashboard-key.pem config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem

# Set proper permissions for certificates
chown -R 1000:1000 config/wazuh_indexer_ssl_certs/
chmod 750 config/wazuh_indexer_ssl_certs/
chmod 400 config/wazuh_indexer_ssl_certs/*-key.pem
chmod 444 config/wazuh_indexer_ssl_certs/*.pem

# Verify all certificate files exist
echo "[INFO] Verifying certificate files..."
for cert_file in root-ca.pem admin.pem admin-key.pem wazuh.indexer.pem wazuh.indexer-key.pem esnode.pem esnode-key.pem wazuh.manager.pem wazuh.manager-key.pem wazuh.dashboard.pem wazuh.dashboard-key.pem root-ca-manager.pem; do
    if [ ! -f "config/wazuh_indexer_ssl_certs/$cert_file" ]; then
        echo "[ERROR] Missing certificate file: $cert_file"
        exit 1
    fi
done

echo "[INFO] All certificate files verified"

# .env file with proper configuration
cat > .env <<EOF
WAZUH_VERSION=4.8.0
ELASTIC_VERSION=7.17.15
CERTS_DIR=./config/wazuh_indexer_ssl_certs
WAZUH_INDEXER_PASSWORD=DefensePoint2024!Indexer
WAZUH_API_PASSWORD=DefensePoint2024!API
WAZUH_DASHBOARD_PASSWORD=DefensePoint2024!Dashboard
WAZUH_INDEXER_PORT=9200
WAZUH_DASHBOARD_PORT=5601
WAZUH_API_PORT=55000
WAZUH_INDEXER_HEAP_SIZE=2g
WAZUH_DATA_PATH=./data
INDEXER_DATA_PATH=./data/wazuh-indexer-data
EOF

# nginx.conf for ALB
cat > nginx.conf <<'EOF'
events {
    worker_connections 1024;
}
http {
    upstream wazuh_dashboard {
        server wazuh.dashboard:5601;
    }
    server {
        listen 80;
        server_name _;

        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }

        location / {
            proxy_pass http://wazuh_dashboard;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_connect_timeout 600;
            proxy_send_timeout 600;
            proxy_read_timeout 600;
            send_timeout 600;
        }
    }
}
EOF

# Cleanup Docker
docker-compose down || true
docker system prune -f

# Start services in proper sequence
echo "[INFO] Starting Wazuh indexer first..."
docker-compose up -d wazuh.indexer

# Wait for indexer to be ready
echo "[INFO] Waiting for indexer to start..."
sleep 60

# Check indexer health
for i in {1..10}; do
    echo "[INFO] Checking indexer health attempt $i..."
    if curl -k -u admin:DefensePoint2024!Indexer https://localhost:9200/_cluster/health 2>/dev/null | grep -q "yellow\|green"; then
        echo "[INFO] Indexer is ready!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "[ERROR] Indexer failed to start properly"
        docker-compose logs wazuh.indexer
        exit 1
    fi
    sleep 15
done

# Initialize security configuration
echo "[INFO] Initializing security configuration..."
docker exec wazuh.indexer bash -c "
    cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools && 
    bash securityadmin.sh \
        -cd ../securityconfig/ \
        -nhnv \
        -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
        -cert /usr/share/wazuh-indexer/certs/admin.pem \
        -key /usr/share/wazuh-indexer/certs/admin-key.pem \
        -p 9200 \
        -icl \
        -h localhost
" || {
    echo "[WARNING] Security admin initialization may have failed, continuing..."
}

# Start remaining services
echo "[INFO] Starting remaining services..."
docker-compose up -d

# Wait for all services
echo "[INFO] Waiting for all services to start..."
sleep 120

# Final health check
echo "[INFO] Performing final health checks..."
for i in {1..15}; do
    echo "[INFO] Health check attempt $i..."
    
    # Check if nginx health endpoint is responding
    if curl -s http://localhost/health >/dev/null 2>&1; then
        echo "[INFO] Nginx proxy is healthy!"
        break
    fi
    
    if [ $i -eq 15 ]; then
        echo "[WARNING] Health check timeout, but continuing..."
        echo "[INFO] Service status:"
        docker-compose ps
        echo "[INFO] Recent logs:"
        docker-compose logs --tail=20
        break
    fi
    
    sleep 20
done

# CloudWatch Agent Setup
echo "[INFO] Installing CloudWatch Agent..."
wget -q https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

mkdir -p /opt/aws/amazon-cloudwatch-agent/etc

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/wazuh-setup.log",
            "log_group_name": "/aws/ec2/defensepoint-wazuh",
            "log_stream_name": "{instance_id}/setup-script",
            "timestamp_format": "%Y-%m-%d %H:%M:%S",
            "timezone": "Local"
          }
        ]
      }
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Add helper aliases
cat >> /home/ubuntu/.bashrc << 'EOF'

# Wazuh Management Aliases
alias wazuh-status='cd /opt/wazuh-docker && docker-compose ps'
alias wazuh-logs='cd /opt/wazuh-docker && docker-compose logs -f'
alias wazuh-health='curl -s http://localhost/health && echo " - OK"'
alias wazuh-indexer-health='curl -k -u admin:DefensePoint2024!Indexer https://localhost:9200/_cluster/health'
alias wazuh-restart='cd /opt/wazuh-docker && docker-compose down && sleep 10 && docker-compose up -d'
EOF

echo "SETUP_COMPLETE=$(date)" > /opt/wazuh-docker/setup-status.txt

echo "[INFO] =========================================="
echo "[INFO] Wazuh setup completed successfully!"
echo "[INFO] Access via ALB: http://<ALB-DNS-NAME>"
echo "[INFO] Default credentials:"
echo "[INFO]   Username: admin"
echo "[INFO]   Password: DefensePoint2024!Indexer"
echo "[INFO] =========================================="
echo "[INFO] Useful commands:"
echo "[INFO]   Check status: wazuh-status"
echo "[INFO]   View logs: wazuh-logs"
echo "[INFO]   Health check: wazuh-health"
echo "[INFO]   Indexer health: wazuh-indexer-health"
echo "[INFO] =========================================="