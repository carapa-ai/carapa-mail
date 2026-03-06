# ── SnappyMail on Alpine 3.23 ─────────────────────────────────────
# Minimal rebuild of djmaze/snappymail using the release tarball
# on a current Alpine base to eliminate inherited CVEs.
#
# Build: docker build -t snappymail:latest webmail/
# ──────────────────────────────────────────────────────────────────
FROM php:8.3-fpm-alpine3.21 AS base

ARG SNAPPYMAIL_VERSION=2.38.2

LABEL org.opencontainers.image.title="snappymail" \
      org.opencontainers.image.description="SnappyMail webmail on Alpine (hardened)" \
      org.opencontainers.image.version="${SNAPPYMAIL_VERSION}"

# ── System packages ──────────────────────────────────────────────
RUN apk add --no-cache \
    ca-certificates \
    nginx \
    supervisor \
    bash \
    wget \
    # PHP extension runtime deps
    freetype libjpeg-turbo libpng \
    icu-libs \
    gnupg gpgme \
    libzip \
    libldap \
    postgresql-libs \
    tidyhtml \
    libuuid

# ── PHP extensions ───────────────────────────────────────────────
# gd
RUN set -eux; \
    apk add --no-cache --virtual .deps freetype-dev libjpeg-turbo-dev libpng-dev; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install -j$(nproc) gd; \
    apk del .deps

# intl
RUN set -eux; \
    apk add --no-cache --virtual .deps icu-dev; \
    docker-php-ext-install -j$(nproc) intl; \
    apk del .deps

# gnupg
RUN set -eux; \
    apk add --no-cache --virtual .deps gpgme-dev $PHPIZE_DEPS; \
    pecl install gnupg; \
    docker-php-ext-enable gnupg; \
    docker-php-source delete; \
    apk del .deps

# ldap
RUN set -eux; \
    apk add --no-cache --virtual .deps openldap-dev; \
    docker-php-ext-install -j$(nproc) ldap; \
    apk del .deps

# pdo_pgsql
RUN set -eux; \
    apk add --no-cache --virtual .deps postgresql-dev; \
    docker-php-ext-install -j$(nproc) pdo_pgsql; \
    apk del .deps

# pdo_mysql + opcache + zip + tidy
RUN set -eux; \
    apk add --no-cache --virtual .deps libzip-dev tidyhtml-dev; \
    docker-php-ext-install -j$(nproc) pdo_mysql opcache zip tidy; \
    apk del .deps

# uuid
RUN set -eux; \
    apk add --no-cache --virtual .deps util-linux-dev $PHPIZE_DEPS; \
    pecl install uuid; \
    docker-php-ext-enable uuid; \
    docker-php-source delete; \
    apk del .deps

# ── Download SnappyMail release ──────────────────────────────────
RUN set -eux; \
    wget -q "https://github.com/the-djmaze/snappymail/releases/download/v${SNAPPYMAIL_VERSION}/snappymail-${SNAPPYMAIL_VERSION}.tar.gz" \
         -O /tmp/snappymail.tar.gz; \
    mkdir -p /snappymail; \
    tar -xzf /tmp/snappymail.tar.gz -C /snappymail; \
    rm /tmp/snappymail.tar.gz; \
    find /snappymail -type d -exec chmod 550 {} \; ; \
    find /snappymail -type f -exec chmod 440 {} \; ; \
    rm -f /snappymail/README.md /snappymail/_include.php; \
    # Move data dir to persistent volume path
    mv /snappymail/data /var/lib/snappymail; \
    chown -R www-data:www-data /snappymail /var/lib/snappymail

# ── Config files ─────────────────────────────────────────────────
# include.php — tells SnappyMail where data lives
RUN printf '<?php\ndefine('"'"'APP_DATA_FOLDER_PATH'"'"', '"'"'/var/lib/snappymail/'"'"');\n?>' \
    > /snappymail/include.php \
    && chown www-data:www-data /snappymail/include.php \
    && chmod 440 /snappymail/include.php

# nginx config
COPY files/nginx.conf /etc/nginx/nginx.conf

# php-fpm config
COPY files/php-fpm.conf /usr/local/etc/php-fpm.d/php-fpm.conf
RUN mv /usr/local/etc/php-fpm.d/docker.conf /usr/local/etc/php-fpm.d/docker.conf.disabled; \
    mv /usr/local/etc/php-fpm.d/www.conf /usr/local/etc/php-fpm.d/www.conf.disabled; \
    mv /usr/local/etc/php-fpm.d/zz-docker.conf /usr/local/etc/php-fpm.d/zz-docker.conf.disabled

# supervisor config
COPY files/supervisor.conf /supervisor.conf

# listener (supervisor event handler for clean shutdown)
COPY files/listener.php /listener.php

# upstream entrypoint
COPY files/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Hardening ────────────────────────────────────────────────────
# Strip SUID/SGID bits
RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /snappymail
VOLUME /var/lib/snappymail
EXPOSE 8888

CMD ["/entrypoint.sh"]
