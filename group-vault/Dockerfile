# Org Vault Container
# Minimal HTTP API for org-level secret storage
# No agent, no chat capability

FROM node:22-alpine

# Install build dependencies for argon2
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install --omit=dev

# Copy source
COPY . .

# Security: run as non-root
USER node

# Expose API port
EXPOSE 18790

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:18790/health || exit 1

# Start server
CMD ["node", "server.js"]
