# syntax=docker/dockerfile:1

FROM node:24-slim AS runtime
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY tsconfig.json ./
COPY src ./src

USER node

ENV NODE_ENV=production \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8081 \
    DOORKING_API_URL=http://api:8080 \
    DOORKING_ALLOW_WRITES=false \
    DOORKING_ALLOW_PHYSICAL=false

EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.MCP_PORT || 8081) + '/mcp/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "src/http.ts"]
