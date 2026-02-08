#!/bin/bash
# OCMT MVP Setup Script
# Run this on your DigitalOcean droplet

set -e

echo "OCMT MVP Setup"
echo "===================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./setup.sh)"
  exit 1
fi

# Install Docker if not present
if ! command -v docker &> /dev/null; then
  echo "📦 Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
fi

# Install Docker Compose plugin if not present
if ! docker compose version &> /dev/null; then
  echo "📦 Installing Docker Compose..."
  apt-get update
  apt-get install -y docker-compose-plugin
fi

# Create app directory
APP_DIR="/opt/ocmt"
mkdir -p $APP_DIR
cd $APP_DIR

echo ""
echo "📝 Configuration needed:"
echo ""

# Get Telegram token
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
  read -p "Enter your Telegram Bot Token (from @BotFather): " TELEGRAM_BOT_TOKEN
fi

# Generate gateway token
GATEWAY_TOKEN=$(openssl rand -hex 32)
echo "Generated Gateway Token: $GATEWAY_TOKEN"
echo "(Save this - you'll need it to access the web UI)"

# Create .env file
cat > .env << EOF
TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN
GATEWAY_TOKEN=$GATEWAY_TOKEN
DOMAIN=${DOMAIN:-localhost}
EOF

echo ""
echo "📄 .env file created"

# Copy config files (assumes they're in current dir or will be created)
echo ""
echo "Now copy your config files to $APP_DIR:"
echo "  - docker-compose.yml"
echo "  - Caddyfile"
echo "  - openclaw.json5"
echo ""
echo "Then run: cd $APP_DIR && docker compose up -d"
echo ""
echo "🔗 Access points:"
echo "  - Web UI: http://YOUR_DROPLET_IP:18789"
echo "  - Telegram: Message your bot!"
echo ""
echo "🔐 Gateway Token (for web UI login): $GATEWAY_TOKEN"
