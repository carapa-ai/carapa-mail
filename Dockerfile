# ── Build stage ────────────────────────────────────────────────────
FROM alpine:3.23 AS build

RUN apk add --no-cache bash curl libstdc++ libgcc

# Install Bun
ARG BUN_VERSION=1.2.5
RUN curl -fsSL https://bun.sh/install | BUN_INSTALL=/opt/bun bash -s "bun-v${BUN_VERSION}" \
    && ln -s /opt/bun/bin/bun /usr/local/bin/bun

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --production --frozen-lockfile

# ── Runtime stage ─────────────────────────────────────────────────
FROM alpine:3.23

LABEL org.opencontainers.image.title="carapa-mail" \
      org.opencontainers.image.description="AI-powered SMTP + IMAP proxy with security scanning" \
      org.opencontainers.image.version="0.9.0"

RUN apk add --no-cache bash ca-certificates libstdc++ libgcc wget openssl

# Bun runtime
COPY --from=build /opt/bun /opt/bun
ENV PATH="/opt/bun/bin:$PATH"

WORKDIR /app

# Deps + source (Bun runs TS directly)
COPY --from=build /app/node_modules node_modules/
COPY package.json bun.lock tsconfig.json ./
COPY src/ src/
COPY prompts/ prompts/

# Non-root user (UID 1000 matches host for bind-mounted dirs)
RUN adduser -D -u 1000 appuser \
    && mkdir -p store certs \
    && chown -R appuser:appuser store certs

# Strip SUID/SGID bits
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

USER appuser

EXPOSE 2525 1993 3200 3466

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:3200/health || exit 1

CMD ["bun", "src/index.ts"]
