#!/bin/bash
# Test runner for nginx htaccess module
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NGINX_BIN="${NGINX_BIN:-/usr/local/nginx/sbin/nginx}"
NGINX_PREFIX="${NGINX_PREFIX:-/usr/local/nginx}"
HTDOCS_ROOT="${SCRIPT_DIR}/htdocs"
NGINX_CONF="${SCRIPT_DIR}/nginx.conf"
NGINX_PID=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_TESTS=0

cleanup() {
    if [ -n "$NGINX_PID" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
        kill "$NGINX_PID" 2>/dev/null || true
        wait "$NGINX_PID" 2>/dev/null || true
    fi
    rm -f "${NGINX_PREFIX}/conf/test.conf"
}

trap cleanup EXIT

# Check nginx binary
if [ ! -x "$NGINX_BIN" ]; then
    echo -e "${RED}Error: nginx binary not found at $NGINX_BIN${NC}"
    echo "Set NGINX_BIN to the correct path"
    exit 1
fi

# Check module
if [ ! -f "${NGINX_PREFIX}/modules/ngx_http_htaccess_module.so" ]; then
    echo -e "${RED}Error: ngx_http_htaccess_module.so not found in ${NGINX_PREFIX}/modules/${NC}"
    echo "Build and install the module first: make install"
    exit 1
fi

# Generate test nginx config
mkdir -p "${NGINX_PREFIX}/logs"
sed "s|__HTDOCS_ROOT__|${HTDOCS_ROOT}|g" "$NGINX_CONF" > "${NGINX_PREFIX}/conf/test.conf"

# Ensure all htdocs files exist
for f in "${HTDOCS_ROOT}"/rewrite/target.html \
         "${HTDOCS_ROOT}"/rewrite/page.html \
         "${HTDOCS_ROOT}"/rewrite/subdir/file.html \
         "${HTDOCS_ROOT}"/redirect/old-page.html \
         "${HTDOCS_ROOT}"/headers/test.html \
         "${HTDOCS_ROOT}"/headers/test.json \
         "${HTDOCS_ROOT}"/headers/style.css \
         "${HTDOCS_ROOT}"/expires/image.jpg \
         "${HTDOCS_ROOT}"/expires/style.css \
         "${HTDOCS_ROOT}"/expires/script.js \
         "${HTDOCS_ROOT}"/expires/page.html \
         "${HTDOCS_ROOT}"/dirindex/index.html \
         "${HTDOCS_ROOT}"/dirindex/fallback.htm \
         "${HTDOCS_ROOT}"/errordoc/custom-404.html \
         "${HTDOCS_ROOT}"/errordoc/page.html \
         "${HTDOCS_ROOT}"/files-block/secret.txt \
         "${HTDOCS_ROOT}"/files-block/public.txt \
         "${HTDOCS_ROOT}"/files-block/data.xml \
         "${HTDOCS_ROOT}"/setenvif/test.html \
         "${HTDOCS_ROOT}"/security/normal.html \
         "${HTDOCS_ROOT}"/access/allowed.html \
         "${HTDOCS_ROOT}"/auth/protected.html \
         "${HTDOCS_ROOT}"/limit/post-auth/page.html \
         "${HTDOCS_ROOT}"/limit/get-only/page.html \
         "${HTDOCS_ROOT}"/ssl-required/page.html \
         "${HTDOCS_ROOT}"/php-values/page.html \
         "${HTDOCS_ROOT}"/setenv/page.html \
         "${HTDOCS_ROOT}"/satisfy/by-ip/page.html \
         "${HTDOCS_ROOT}"/satisfy/strict/page.html \
         "${HTDOCS_ROOT}"/auth-sha/page.html \
         "${HTDOCS_ROOT}"/auth-apr1/page.html \
         "${HTDOCS_ROOT}"/groups/page.html \
         "${HTDOCS_ROOT}"/groups/files-secret.html \
         "${HTDOCS_ROOT}"/reqheader/page.html; do
    dir=$(dirname "$f")
    mkdir -p "$dir"
    if [ ! -f "$f" ]; then
        basename=$(basename "$f")
        echo "<html><body>$basename</body></html>" > "$f"
    fi
done

# Create htpasswd file for auth tests
# testuser:testpass (SHA-512 crypt)
if [ ! -f "${HTDOCS_ROOT}/auth/.htpasswd" ]; then
    mkdir -p "${HTDOCS_ROOT}/auth"
    # Generate using openssl (SHA-512 format supported by system crypt())
    HASH=$(openssl passwd -6 "testpass")
    echo "testuser:${HASH}" > "${HTDOCS_ROOT}/auth/.htpasswd"
    HASH2=$(openssl passwd -6 "otherpass")
    echo "otheruser:${HASH2}" >> "${HTDOCS_ROOT}/auth/.htpasswd"
fi

# Substitute __HTDOCS_ROOT__ placeholders in .htaccess files that need
# absolute paths (AuthUserFile, AuthGroupFile, etc.). Done in-place; safe to
# re-run because the placeholder is only present in pristine checked-in files.
for f in "${HTDOCS_ROOT}/auth/.htaccess" \
         "${HTDOCS_ROOT}/limit/post-auth/.htaccess" \
         "${HTDOCS_ROOT}/satisfy/by-ip/.htaccess" \
         "${HTDOCS_ROOT}/satisfy/strict/.htaccess" \
         "${HTDOCS_ROOT}/auth-sha/.htaccess" \
         "${HTDOCS_ROOT}/auth-apr1/.htaccess" \
         "${HTDOCS_ROOT}/groups/.htaccess"; do
    [ -f "$f" ] && sed -i "s|__HTDOCS_ROOT__|${HTDOCS_ROOT}|g" "$f"
done

# Generate {SHA} and $apr1$ htpasswd files for native runs (Docker generates
# these in the image build step, but native users need them too).
if command -v sha1sum >/dev/null 2>&1 && command -v xxd >/dev/null 2>&1; then
    if [ ! -f "${HTDOCS_ROOT}/auth-sha/.htpasswd" ]; then
        mkdir -p "${HTDOCS_ROOT}/auth-sha"
        SHA_HASH=$(printf '%s' 'testpass' | sha1sum | awk '{print $1}' | \
                   xxd -r -p | base64)
        echo "shauser:{SHA}${SHA_HASH}" > "${HTDOCS_ROOT}/auth-sha/.htpasswd"
    fi
fi
if command -v htpasswd >/dev/null 2>&1; then
    if [ ! -f "${HTDOCS_ROOT}/auth-apr1/.htpasswd" ]; then
        mkdir -p "${HTDOCS_ROOT}/auth-apr1"
        htpasswd -bcm "${HTDOCS_ROOT}/auth-apr1/.htpasswd" apruser testpass
    fi
fi
if [ ! -f "${HTDOCS_ROOT}/groups/.htgroup" ]; then
    mkdir -p "${HTDOCS_ROOT}/groups"
    printf 'admins: testuser\nusers: testuser otheruser\nempty:\n' \
        > "${HTDOCS_ROOT}/groups/.htgroup"
fi

# Start nginx
echo "Starting nginx for tests..."
"$NGINX_BIN" -c "${NGINX_PREFIX}/conf/test.conf" -p "$NGINX_PREFIX" &
NGINX_PID=$!

# Wait for nginx to be ready
for i in $(seq 1 30); do
    if curl -s -o /dev/null http://127.0.0.1:8181/ 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! curl -s -o /dev/null http://127.0.0.1:8181/ 2>/dev/null; then
    echo -e "${RED}Error: nginx failed to start${NC}"
    cat "${NGINX_PREFIX}/logs/error.log" 2>/dev/null | tail -20
    exit 1
fi

echo -e "${GREEN}nginx started (PID: $NGINX_PID)${NC}"
echo ""

# Run all test files
for test_file in "${SCRIPT_DIR}"/*.t.sh; do
    if [ ! -f "$test_file" ]; then
        continue
    fi

    test_name=$(basename "$test_file" .t.sh)
    echo -e "${YELLOW}=== $test_name ===${NC}"

    # Source helpers fresh for each test (reset counters)
    TESTS_PASSED=0
    TESTS_FAILED=0
    TESTS_TOTAL=0
    source "${SCRIPT_DIR}/helpers.sh"

    # Run test
    source "$test_file"

    TOTAL_PASSED=$((TOTAL_PASSED + TESTS_PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + TESTS_FAILED))
    TOTAL_TESTS=$((TOTAL_TESTS + TESTS_TOTAL))

    echo ""
done

# Final summary
echo "======================================"
echo "TOTAL RESULTS"
echo "======================================"
if [ "$TOTAL_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All $TOTAL_TESTS tests passed!${NC}"
else
    echo -e "${RED}$TOTAL_FAILED of $TOTAL_TESTS tests failed${NC}"
    echo -e "${GREEN}$TOTAL_PASSED passed${NC}, ${RED}$TOTAL_FAILED failed${NC}"
fi
echo "======================================"

exit $TOTAL_FAILED
