FROM oven/bun:latest AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

FROM oven/bun:latest
WORKDIR /app

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY --from=deps /app/node_modules ./node_modules
COPY package.json bun.lock ./
COPY src/ ./src/
COPY prompts/ ./prompts/

RUN mkdir store && chown 1000:1000 store

USER 1000:1000

CMD ["bun", "src/index.ts"]
