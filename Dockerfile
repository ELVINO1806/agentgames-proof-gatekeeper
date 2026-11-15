FROM node:24-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
RUN sh scripts/download-circuits.sh
ENV GATEKEEPER_WASM=/app/circuits/gatekeeper.wasm
ENV GATEKEEPER_ZKEY=/app/circuits/gatekeeper_final.zkey
ENV PORT=8787
EXPOSE 8787
CMD ["node", "index.js"]
