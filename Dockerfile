FROM ubuntu:24.04

ARG NGINX_VERSION=1.28.2

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcre2-dev \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    wget \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and extract nginx source
RUN wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz \
    && rm nginx-${NGINX_VERSION}.tar.gz

# Copy module source
COPY *.c *.h config /module/

# Build nginx with module
RUN cd /nginx-${NGINX_VERSION} \
    && ./configure \
        --with-compat \
        --with-http_ssl_module \
        --with-http_realip_module \
        --add-dynamic-module=/module \
    && make -j$(nproc) modules \
    && make -j$(nproc) \
    && make install

# Install module
RUN mkdir -p /usr/local/nginx/modules \
    && cp /nginx-${NGINX_VERSION}/objs/ngx_http_htaccess_module.so /usr/local/nginx/modules/

# Copy test files
COPY t/ /tests/t/

# Generate htpasswd and fix paths
RUN HTDOCS=/tests/t/htdocs \
    && HASH=$(openssl passwd -6 "testpass") \
    && echo "testuser:${HASH}" > "$HTDOCS/auth/.htpasswd" \
    && HASH2=$(openssl passwd -6 "otherpass") \
    && echo "otheruser:${HASH2}" >> "$HTDOCS/auth/.htpasswd" \
    && sed -i "s|__HTDOCS_ROOT__|${HTDOCS}|g" "$HTDOCS/auth/.htaccess" \
    && chmod +x /tests/t/run_tests.sh /tests/t/helpers.sh /tests/t/*.t.sh

WORKDIR /tests

ENV NGINX_BIN=/usr/local/nginx/sbin/nginx
ENV NGINX_PREFIX=/usr/local/nginx

EXPOSE 8181

CMD ["/tests/t/run_tests.sh"]
