# DEPLOYMENT.md: Production Deployment & Hardening Guide

## 1. Environment Configuration (.env)

```env
NODE_ENV=production
PORT=4000
DATABASE_URL=postgresql://loki_user:secure_password@localhost:5432/loki_production
JWT_SECRET=super-secret-random-jwt-signing-key-min-64-chars
AUDIT_HMAC_SECRET=super-secret-random-audit-hmac-key-min-64-chars
CORS_ORIGIN=https://vault.agency.com
```

## 2. Production Docker Deployment

```dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist
EXPOSE 4000
CMD ["node", "dist/server.js"]
```

## 3. Reverse Proxy & Security Headers (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name vault.agency.com;

    ssl_protocols TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers (Section 38)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;" always;

    location / {
        proxy_pass http://localhost:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```
