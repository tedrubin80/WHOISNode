# ecosystem.config.js - PM2 Configuration
module.exports = {
  apps: [{
    name: 'whois-backend',
    script: 'server.js',
    instances: 2,
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production',
      PORT: 3001
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true,
    max_memory_restart: '500M',
    node_args: '--max-old-space-size=512'
  }]
}

---

# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Start the application
CMD ["npm", "start"]

---

# docker-compose.yml
version: '3.8'

services:
  whois-backend:
    build: .
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - PORT=3001
    restart: unless-stopped
    volumes:
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3001/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - whois-backend
    restart: unless-stopped

---

# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream whois_backend {
        server whois-backend:3001;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    server {
        listen 80;
        server_name your-domain.com;

        # Redirect HTTP to HTTPS
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl;
        server_name your-domain.com;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        # API proxy
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://whois_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 30s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }

        # Health check
        location /health {
            proxy_pass http://whois_backend/health;
        }

        # Serve static frontend files
        location / {
            root /var/www/html;
            try_files $uri $uri/ /index.html;
        }
    }
}

---

# .env.example
NODE_ENV=production
PORT=3001

# Optional API Keys (for better rate limits)
WHOISJSON_API_KEY=your_whoisjson_api_key
WHOISXML_API_KEY=your_whoisxml_api_key

# Logging
LOG_LEVEL=info

---

# deploy.sh - Simple deployment script
#!/bin/bash

echo "Deploying WHOIS Backend Server..."

# Pull latest code
git pull origin main

# Install/update dependencies
npm ci --only=production

# Create logs directory
mkdir -p logs

# Check if PM2 is running
if pm2 list | grep -q "whois-backend"; then
    echo "Restarting existing PM2 process..."
    pm2 restart whois-backend
else
    echo "Starting new PM2 process..."
    pm2 start ecosystem.config.js
fi

# Save PM2 configuration
pm2 save

echo "Deployment complete!"
echo "Check status: pm2 status"
echo "View logs: pm2 logs whois-backend"

---

# install.sh - Initial server setup
#!/bin/bash

echo "Setting up WHOIS Backend Server..."

# Update system
apt update && apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Install PM2 globally
npm install -g pm2

# Install nginx (optional)
apt install -y nginx

# Clone your repository
# git clone https://github.com/yourusername/whois-backend.git
# cd whois-backend

# Install dependencies
npm ci --only=production

# Create logs directory
mkdir -p logs

# Setup PM2 startup
pm2 startup
pm2 start ecosystem.config.js
pm2 save

# Setup nginx (if using)
# cp nginx.conf /etc/nginx/sites-available/whois-backend
# ln -s /etc/nginx/sites-available/whois-backend /etc/nginx/sites-enabled/
# nginx -t && systemctl restart nginx

echo "Setup complete!"
echo "Your WHOIS backend is running on port 3001"
echo "Check status: pm2 status"