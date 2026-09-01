FROM node:20-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip curl ca-certificates unzip lua5.1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY . .
RUN chmod +x /app/engine/lune
RUN cd /app/engine/v1sexy && npm install --omit=dev

ENV NODE_ENV=production
ENV PORT=8787
CMD ["node", "server.js"]
