#!/bin/bash
# Stress test: hammer nginx with concurrent traffic and verify
#   (a) it does not crash
#   (b) it does not leak memory
#   (c) request error rate stays at zero
#
# Run inside the test container:
#   docker run --rm nginx-htaccess-test bash /tests/t/stress.sh
#
# Uses Apache Bench (ab) which comes with apache2-utils (already in the image).

set -u
HTDOCS_ROOT=/tests/t/htdocs
NGINX_PREFIX=/usr/local/nginx
NGINX_BIN=$NGINX_PREFIX/sbin/nginx

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Prepare files the same way run_tests.sh does
mkdir -p $HTDOCS_ROOT/{rewrite,redirect,headers,expires,dirindex,errordoc,files-block,setenvif,security,access,auth,limit/post-auth,limit/get-only,ssl-required,php-values,setenv,satisfy/by-ip,satisfy/strict,auth-sha,auth-apr1,groups,reqheader}
mkdir -p $HTDOCS_ROOT/no-htaccess
for f in $HTDOCS_ROOT/rewrite/page.html \
         $HTDOCS_ROOT/auth/protected.html \
         $HTDOCS_ROOT/cms/wordpress/sample-post \
         $HTDOCS_ROOT/setenv/page.html \
         $HTDOCS_ROOT/php-values/page.html \
         $HTDOCS_ROOT/no-htaccess/test.html \
         $HTDOCS_ROOT/auth-apr1/page.html; do
    mkdir -p "$(dirname "$f")"
    [ -f "$f" ] || echo "<html><body>$(basename "$f")</body></html>" > "$f"
done

# htpasswd / htgroup
[ -f $HTDOCS_ROOT/auth/.htpasswd ] || {
    HASH=$(openssl passwd -6 testpass); echo "testuser:$HASH" > $HTDOCS_ROOT/auth/.htpasswd
}
[ -f $HTDOCS_ROOT/auth-apr1/.htpasswd ] || htpasswd -bcm $HTDOCS_ROOT/auth-apr1/.htpasswd apruser testpass 2>/dev/null
[ -f $HTDOCS_ROOT/groups/.htgroup ] || printf 'admins: testuser\nusers: testuser\n' > $HTDOCS_ROOT/groups/.htgroup

# Substitute __HTDOCS_ROOT__ placeholders
for f in $HTDOCS_ROOT/auth/.htaccess \
         $HTDOCS_ROOT/auth-apr1/.htaccess \
         $HTDOCS_ROOT/limit/post-auth/.htaccess \
         $HTDOCS_ROOT/satisfy/by-ip/.htaccess \
         $HTDOCS_ROOT/satisfy/strict/.htaccess \
         $HTDOCS_ROOT/auth-sha/.htaccess \
         $HTDOCS_ROOT/groups/.htaccess; do
    [ -f "$f" ] && sed -i "s|__HTDOCS_ROOT__|$HTDOCS_ROOT|g" "$f"
done

sed "s|__HTDOCS_ROOT__|$HTDOCS_ROOT|g" /tests/t/nginx.conf > $NGINX_PREFIX/conf/test.conf

# Start nginx in background with verbose logging, capture PID
mkdir -p $NGINX_PREFIX/logs
> $NGINX_PREFIX/logs/error.log
$NGINX_BIN -c $NGINX_PREFIX/conf/test.conf -p $NGINX_PREFIX &
NPID=$!
sleep 1

if ! kill -0 $NPID 2>/dev/null; then
    echo -e "${RED}nginx failed to start${NC}"
    tail -20 $NGINX_PREFIX/logs/error.log
    exit 1
fi

# Capture RSS at start (worker process)
worker_rss() {
    local wpid=$(pgrep -P $NPID | head -1)
    [ -n "$wpid" ] && cat /proc/$wpid/status 2>/dev/null | awk '/^VmRSS:/{print $2}' || echo 0
}
START_RSS=$(worker_rss)
echo -e "${YELLOW}nginx PID=$NPID  worker RSS=${START_RSS} KB${NC}"
echo ""

# ----------------------------------------------------------------------
# Scenario runner
# ----------------------------------------------------------------------
total_pass=0; total_fail=0

run_scenario() {
    local label="$1"
    local url="$2"
    local n="$3"
    local c="$4"
    shift 4
    local extra_args="$@"

    echo -e "${YELLOW}>>> $label${NC}"
    echo "    url=$url  requests=$n  concurrency=$c"
    out=$(ab -q -n "$n" -c "$c" $extra_args "http://127.0.0.1:8181$url" 2>&1)

    fails=$(echo "$out" | awk '/^Failed requests:/{print $3}')
    non2xx=$(echo "$out" | awk '/^Non-2xx responses:/{print $3}')
    rps=$(echo "$out" | awk '/^Requests per second:/{print $4}')
    mean=$(echo "$out" | awk '/^Time per request:.*mean\)/{print $4; exit}')

    fails=${fails:-0}; non2xx=${non2xx:-0}; rps=${rps:-?}; mean=${mean:-?}

    # If the user passed -H Auth or similar, expected status is 200; otherwise
    # treat non-2xx as expected when the caller indicated it via NON2XX_OK.
    if [ "$fails" = "0" ] && { [ "$non2xx" = "0" ] || [ "${NON2XX_OK:-0}" = "1" ]; }; then
        echo -e "    ${GREEN}OK${NC}  rps=$rps  mean=${mean}ms  fails=$fails  non2xx=$non2xx"
        total_pass=$((total_pass+1))
    else
        echo -e "    ${RED}FAIL${NC}  rps=$rps  mean=${mean}ms  fails=$fails  non2xx=$non2xx"
        total_fail=$((total_fail+1))
    fi
    NON2XX_OK=0
}

# 1. Pure static, no .htaccess in path - baseline overhead of htaccess off
run_scenario "Baseline (no .htaccess)" /no-htaccess/test.html 5000 50 ; :

# 2. Static file with .htaccess + SetEnvIf + add_header chain
run_scenario "Static + SetEnv chain" /setenv/page.html 5000 50 ; :

# 3. Rewrite-heavy WordPress-style URL (regex match, no rewrite fires)
run_scenario "WordPress pretty permalink rewrite" /cms/wordpress/sample-post 5000 50 ; :

# 4. Basic auth with bcrypt-class hash (SHA-512 in our htpasswd)
run_scenario "Basic auth (SHA-512 crypt)" /auth/protected.html 2000 25 \
    -A "testuser:testpass"

# 5. Basic auth with APR1 (the heavy 1000-round MD5 — verifies it does not melt)
run_scenario "Basic auth (\$apr1\$ Apache-MD5)" /auth-apr1/page.html 2000 25 \
    -A "apruser:testpass"

# 6. RequestHeader path (modifies r->headers_in on every request)
run_scenario "RequestHeader modification" /reqheader/__req 5000 50 ; :

# 7. php_value variable expansion path
run_scenario "php_value collection" /php-values/__pv 5000 50 ; :

# 8. 401 responses (Basic auth WITHOUT credentials) - verifies auth fast-fail
NON2XX_OK=1 run_scenario "401 fast-fail (no creds)" /auth/protected.html 5000 50

# ----------------------------------------------------------------------
# Post-stress checks
# ----------------------------------------------------------------------
echo ""
echo -e "${YELLOW}=== Post-stress checks ===${NC}"

# nginx still alive?
if kill -0 $NPID 2>/dev/null; then
    echo -e "${GREEN}nginx master process still running${NC}"
else
    echo -e "${RED}nginx master process DIED during stress${NC}"
    total_fail=$((total_fail+1))
fi

WPID=$(pgrep -P $NPID | head -1)
if [ -n "$WPID" ] && kill -0 $WPID 2>/dev/null; then
    END_RSS=$(cat /proc/$WPID/status 2>/dev/null | awk '/^VmRSS:/{print $2}')
    GROWTH=$((END_RSS - START_RSS))
    echo "Worker RSS: ${START_RSS} KB -> ${END_RSS} KB  (delta=${GROWTH} KB)"
    # Allow up to 8 MB growth (parser cache fills up); flag anything beyond
    if [ "$GROWTH" -gt 8192 ]; then
        echo -e "${RED}Suspicious memory growth (>8 MB)${NC}"
        total_fail=$((total_fail+1))
    else
        echo -e "${GREEN}Memory growth within bounds${NC}"
    fi
else
    echo -e "${RED}worker process gone${NC}"
    total_fail=$((total_fail+1))
fi

# crit/emerg/alert in error log
CRIT=$(grep -E "\[(alert|crit|emerg)\]" $NGINX_PREFIX/logs/error.log | wc -l)
if [ "$CRIT" -eq 0 ]; then
    echo -e "${GREEN}No alert/crit/emerg entries in error log${NC}"
else
    echo -e "${RED}$CRIT alert/crit/emerg entries:${NC}"
    grep -E "\[(alert|crit|emerg)\]" $NGINX_PREFIX/logs/error.log | head -5
    total_fail=$((total_fail+1))
fi

# Final liveness probe
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8181/setenv/page.html | grep -q 200; then
    echo -e "${GREEN}Final liveness probe OK${NC}"
else
    echo -e "${RED}Final liveness probe FAILED${NC}"
    total_fail=$((total_fail+1))
fi

kill $NPID 2>/dev/null
wait $NPID 2>/dev/null

echo ""
echo "======================================"
if [ "$total_fail" -eq 0 ]; then
    echo -e "${GREEN}Stress test: all $total_pass scenarios passed${NC}"
else
    echo -e "${RED}Stress test: $total_fail of $((total_pass+total_fail)) scenarios failed${NC}"
fi
echo "======================================"
exit $total_fail
