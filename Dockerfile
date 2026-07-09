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
    apache2-utils \
    xxd \
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

# Generate htpasswd files (multiple hash formats) and fix paths
RUN HTDOCS=/tests/t/htdocs \
    && HASH=$(openssl passwd -6 "testpass") \
    && echo "testuser:${HASH}" > "$HTDOCS/auth/.htpasswd" \
    && HASH2=$(openssl passwd -6 "otherpass") \
    && echo "otheruser:${HASH2}" >> "$HTDOCS/auth/.htpasswd" \
    # {SHA} format: base64(sha1(password)) \
    && SHA_HASH=$(printf '%s' 'testpass' | sha1sum | awk '{print $1}' | xxd -r -p | base64) \
    && echo "shauser:{SHA}${SHA_HASH}" > "$HTDOCS/auth-sha/.htpasswd" \
    # $apr1$ format: Apache MD5 (htpasswd -m) \
    && htpasswd -bcm "$HTDOCS/auth-apr1/.htpasswd" apruser testpass \
    # .htgroup file: groups for Require group tests \
    && printf 'admins: testuser\nusers: testuser otheruser\nempty:\n' > "$HTDOCS/groups/.htgroup" \
    # apply __HTDOCS_ROOT__ substitution \
    && for f in "$HTDOCS/auth/.htaccess" \
                "$HTDOCS/limit/post-auth/.htaccess" \
                "$HTDOCS/satisfy/by-ip/.htaccess" \
                "$HTDOCS/satisfy/strict/.htaccess" \
                "$HTDOCS/auth-sha/.htaccess" \
                "$HTDOCS/auth-apr1/.htaccess" \
                "$HTDOCS/groups/.htaccess" \
                "$HTDOCS/sec/inherit/.htaccess" \
                "$HTDOCS/sec/satisfy-block/.htaccess"; do \
        [ -f "$f" ] && sed -i "s|__HTDOCS_ROOT__|${HTDOCS}|g" "$f"; \
    done \
    && chmod +x /tests/t/run_tests.sh /tests/t/helpers.sh /tests/t/*.t.sh

WORKDIR /tests

ENV NGINX_BIN=/usr/local/nginx/sbin/nginx
ENV NGINX_PREFIX=/usr/local/nginx

EXPOSE 8181

CMD ["/tests/t/run_tests.sh"]
