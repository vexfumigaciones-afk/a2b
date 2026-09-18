# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/playwright:v1.55.0-noble

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY lib ./lib
COPY server.js ./server.js
COPY public ./public

RUN mkdir -p /data && node --check server.js && node --check lib/crypto-store.js && node --check lib/aspel.js

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/data \
    NODE_OPTIONS=--max-old-space-size=128 \
    MALLOC_ARENA_MAX=2

EXPOSE 3000
CMD ["npm","start"]
