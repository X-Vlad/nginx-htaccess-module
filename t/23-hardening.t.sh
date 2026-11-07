#!/bin/bash
# Regression tests for the 2026 security hardening pass.

# M-1: per-directory RewriteRule subject must not include the directory prefix.
begin_test "nested RewriteRule ^secret\\.txt$ blocks"
assert_status GET /sec/hardening/nested/secret.txt 403

begin_test "nested RewriteRule non-matching file served"
assert_status GET /sec/hardening/nested/page.html 200

# A-2/A-3: Apache netmask, partial and out-of-range prefixes must fail closed.
begin_test "Deny from a.b.c.d/netmask blocks"
assert_status GET /sec/hardening/ipmask/page.html 403

begin_test "Deny from partial address blocks"
assert_status GET /sec/hardening/ippartial/page.html 403

begin_test "Deny from out-of-range prefix blocks"
assert_status GET /sec/hardening/ipbad/page.html 403

# C6: RequireAll with Require all granted + Require ip must require both.
begin_test "<RequireAll> does not let Require all granted waive Require ip"
assert_status GET /sec/hardening/requireall/page.html 403

# P-7: negated RewriteRule.
begin_test "negated RewriteRule blocks non-matching file"
assert_status GET /sec/hardening/noneg/secret.txt 403

begin_test "negated RewriteRule leaves matching file alone"
assert_status GET /sec/hardening/noneg/public.html 200

# C4b: Header merge without a value must not crash the worker.
begin_test "Header merge without value is harmless"
assert_status GET /sec/hardening/hdrmerge/page.html 200

# P-1: malformed FilesMatch must fail closed, not silently drop the block.
begin_test "empty FilesMatch tag fails closed"
assert_status GET /sec/hardening/badfilesmatch/page.html 500

# C4: decoded CR/LF must not split the Location header.
begin_test "CRLF in redirect target is rejected"
headers=$(curl -s -D - -o /dev/null "http://127.0.0.1:8181/sec/hardening/crlf/x%0d%0aX-Injected:%201")
status=$(printf '%s' "$headers" | head -1 | awk '{print $2}')
if [ "$status" != "301" ] && [ "$status" != "302" ] \
   && ! printf '%s' "$headers" | grep -qi '^X-Injected:'; then
    pass
else
    fail "expected no redirect with X-Injected, got: $headers"
fi

# C5: SetEnv must not overwrite nginx built-ins such as $host.
begin_test "SetEnv cannot overwrite \$host"
body=$(curl -s "http://127.0.0.1:8181/sec/hardening/builtin/")
if printf '%s' "$body" | grep -q 'HOST=\[127.0.0.1\]'; then
    pass
else
    fail "expected original host, got: $body"
fi

# C2b: encoded dot-dot must not bypass the rules of the real target directory.
begin_test "encoded dot-dot cannot bypass per-directory deny"
body=$(curl -s --path-as-is \
    "http://127.0.0.1:8181/sec/hardening/nested/%2e%2e/ssisecret/secret.txt")
if printf '%s' "$body" | grep -q 'SSI-SECRET'; then
    fail "encoded traversal leaked a denied file: $body"
else
    pass
fi

# H-3: file tests must not probe outside the document root.
begin_test "RewriteCond -f outside root returns no match"
body=$(curl -s "http://127.0.0.1:8181/sec/hardening/oracle/any?p=etc/passwd")
if printf '%s' "$body" | grep -q 'YES-ORACLE'; then
    fail "outside-root file test matched: $body"
else
    pass
fi

# C8: dynamic root must fail closed instead of silently disabling rules.
begin_test "variable root fails closed"
assert_status GET /sec/hardening/dynroot/page.html 500

# C3: subrequests (SSI) must not bypass .htaccess access rules.
begin_test "SSI subrequest cannot read a denied file"
body=$(curl -s "http://127.0.0.1:8181/sec/hardening/ssi/index.shtml")
if printf '%s' "$body" | grep -q 'SSI-SECRET'; then
    fail "denied file leaked through SSI: $body"
else
    pass
fi

begin_test "SSI subrequest cannot bypass RewriteRule [F]"
body=$(curl -s "http://127.0.0.1:8181/sec/hardening/ssi-rw/index.shtml")
if printf '%s' "$body" | grep -q 'SSI-RW-SECRET'; then
    fail "rewrite-denied file leaked through SSI: $body"
else
    pass
fi

# A-1: oversized {SHA} hash must not smash the stack.
begin_test "oversized {SHA} hash is rejected without a crash"
sha_file="${HTDOCS_ROOT}/auth-sha/.htpasswd"
sha_save="${sha_file}.hardening-save"
cp "$sha_file" "$sha_save" 2>/dev/null || true
printf 'evil:{SHA}%s\n' "$(head -c 600 /dev/zero | tr '\0' A | base64 -w0)" > "$sha_file"
status=$(curl -s -o /dev/null -w "%{http_code}" -u "evil:x" "${BASE_URL}/auth-sha/page.html")
mv "$sha_save" "$sha_file" 2>/dev/null || true
if [ "$status" = "401" ] || [ "$status" = "500" ]; then
    pass
else
    fail "expected 401/500 for oversized hash, got $status"
fi

# R-2: FallbackResource/ErrorDocument internal redirects must not leak fds.
begin_test "FallbackResource does not leak file descriptors"
pid=$(pgrep -f 'nginx: worker' | head -1)
if [ -n "$pid" ]; then
    before=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
    for i in $(seq 1 100); do
        curl -s -o /dev/null "http://127.0.0.1:8181/sec/fallback/no-such-route-$i"
    done
    after=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
    if [ $((after - before)) -le 5 ]; then
        pass
    else
        fail "fd growth $before -> $after"
    fi
else
    fail "worker pid not found"
fi

# H-1/H-2: symlinked .htaccess must be rejected, and its content must not
# be written to the error log.
begin_test "symlinked .htaccess fails closed and logs no content"
symdir="${HTDOCS_ROOT}/sec/hardening/symlink"
rm -rf "$symdir"
mkdir -p "$symdir"
printf 'symlink page\n' > "$symdir/page.html"
printf 'DB_PASSWORD=hardening-secret-42\n' > "$symdir/secret.env"
ln -s "$symdir/secret.env" "$symdir/.htaccess"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/sec/hardening/symlink/page.html")
if [ "$status" = "500" ] \
   && ! grep -q 'hardening-secret-42' "${NGINX_PREFIX}/logs/error.log"; then
    pass
else
    fail "expected 500 without logging content, got $status"
fi
rm -rf "$symdir"

# M-2: next request must see an .htaccess change (no 64-request window).
begin_test "inotify change is visible on the next request"
before=$(curl -s -o /dev/null -w '%{http_code}' \
    "${BASE_URL}/sec/hardening/inotify/page.html")
printf 'Require all denied\n' > "${HTDOCS_ROOT}/sec/hardening/inotify/.htaccess"
after=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/sec/hardening/inotify/page.html")
printf 'Require all granted\n' > "${HTDOCS_ROOT}/sec/hardening/inotify/.htaccess"
if [ "$before" = "200" ] && [ "$after" = "403" ]; then
    pass
else
    fail "expected 200 then 403, got $before/$after"
fi

# ---------------------------------------------------------------------------
# Residual hardening: ErrorDocument status/precedence, inherited auth,
# dangerous PHP settings, protected headers, Expires off, FollowSymLinks,
# cross-tenant ownership and symlink isolation.
# ---------------------------------------------------------------------------

begin_test "ErrorDocument: module 403 keeps original status and custom body"
body=$(curl -s -w '\n%{http_code}' "${BASE_URL}/errordoc/forbidden/page.html")
code=${body##*$'\n'}
if [ "$code" = "403" ] && printf '%s' "$body" | grep -q 'ERROR-DOC-403'; then
    pass
else
    fail "expected 403 + custom error page, got: $body"
fi

begin_test "ErrorDocument: deepest .htaccess wins"
body=$(curl -s -w '\n%{http_code}' "${BASE_URL}/errordoc/forbidden/child/page.html")
code=${body##*$'\n'}
if [ "$code" = "403" ] && printf '%s' "$body" | grep -q 'ERROR-DOC-403-CHILD'; then
    pass
else
    fail "expected child error page, got: $body"
fi

begin_test "auth config inherits across .htaccess files"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/inherit-auth/child/page.html")
status_auth=$(curl -s -o /dev/null -w "%{http_code}" -u testuser:testpass \
    "${BASE_URL}/inherit-auth/child/page.html")
if [ "$status" = "401" ] && [ "$status_auth" = "200" ]; then
    pass
else
    fail "expected 401/200, got $status/$status_auth"
fi

begin_test "dangerous php_value is not forwarded to PHP_VALUE"
body=$(curl -s "${BASE_URL}/sec/hardening/phpdanger/__pv")
if printf '%s' "$body" | grep -q 'auto_prepend_file'; then
    fail "dangerous setting leaked: $body"
else
    pass
fi

begin_test "Header unset cannot remove a security header from a parent"
headers=$(curl -s -D - -o /dev/null \
    "${BASE_URL}/sec/hardening/prothdr/child/page.html")
if printf '%s' "$headers" | grep -qi '^X-Frame-Options: DENY'; then
    pass
else
    fail "X-Frame-Options was removed: $headers"
fi

begin_test "ExpiresActive Off removes the parent Expires header"
parent_headers=$(curl -s -D - -o /dev/null \
    "${BASE_URL}/sec/hardening/expiresoff/page.html")
child_headers=$(curl -s -D - -o /dev/null \
    "${BASE_URL}/sec/hardening/expiresoff/child/page.html")
if printf '%s' "$parent_headers" | grep -qi '^Expires:' \
   && ! printf '%s' "$child_headers" | grep -qi '^Expires:'; then
    pass
else
    fail "parent/child Expires mismatch: $child_headers"
fi

begin_test "Options -FollowSymLinks blocks a symlinked file"
nofollow="${HTDOCS_ROOT}/sec/hardening/nofollow"
rm -f "$nofollow/link.html"
ln -s page.html "$nofollow/link.html"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/sec/hardening/nofollow/link.html")
rm -f "$nofollow/link.html"
if [ "$status" = "403" ]; then
    pass
else
    fail "expected 403 for symlink, got $status"
fi

begin_test "header cap overflow fails closed"
caps="${HTDOCS_ROOT}/sec/hardening/caps"
rm -rf "$caps"
mkdir -p "$caps"
printf 'caps page\n' > "$caps/page.html"
i=1
while [ "$i" -le 65 ]; do
    printf 'Header set X-Cap-%s value\n' "$i" >> "$caps/.htaccess"
    i=$((i + 1))
done
status=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/sec/hardening/caps/page.html")
rm -rf "$caps"
if [ "$status" = "500" ]; then
    pass
else
    fail "expected 500, got $status"
fi

# Cross-tenant simulation: /tenant-a/ is a docroot alias; tenant-b is a
# different Unix owner.  Symlinks and auth files must not cross the boundary.
begin_test "cross-tenant isolation (symlink, hardlink, auth file)"
xt=/tmp/ngx-htaccess-tests
rm -rf "$xt"
mkdir -p "$xt/tenant-a/hard" "$xt/tenant-a/sym" "$xt/tenant-b"
printf 'A-PAGE\n' > "$xt/tenant-a/page.html"
printf 'hard page\n' > "$xt/tenant-a/hard/page.html"
printf 'sym page\n' > "$xt/tenant-a/sym/page.html"
printf 'Require all granted\n' > "$xt/tenant-a/.htaccess"
printf 'TENANT-B-SECRET\n' > "$xt/tenant-b/secret.txt"
printf 'Require all granted\n' > "$xt/tenant-b/evil.htaccess"
chmod 755 "$xt" "$xt/tenant-a" "$xt/tenant-a/hard" "$xt/tenant-a/sym" \
          "$xt/tenant-b"
find "$xt" -type f -exec chmod 644 {} +
chown -R 1001:1001 "$xt/tenant-a"
chown -R 1002:1002 "$xt/tenant-b"

# 1. symlinked directory into tenant B
ln -s ../tenant-b "$xt/tenant-a/evil"
status_escape=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/tenant-a/evil/secret.txt")

# 2. hardlinked .htaccess owned by tenant B (create after chown so the
#    inode keeps tenant B's ownership)
ln "$xt/tenant-b/evil.htaccess" "$xt/tenant-a/hard/.htaccess"
status_hard=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/tenant-a/hard/page.html")

# 3. symlinked .htaccess
ln -s ../../tenant-b/evil.htaccess "$xt/tenant-a/sym/.htaccess"
status_sym=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/tenant-a/sym/page.html")

# 4. AuthUserFile pointing at tenant B's password database
mkdir -p "$xt/tenant-a/auth"
printf 'auth page\n' > "$xt/tenant-a/auth/page.html"
htpasswd -bcm "$xt/tenant-b/.htpasswd" buser bpass >/dev/null 2>&1
printf 'AuthType Basic\nAuthName "T"\nAuthUserFile %s\nRequire valid-user\n' \
    "$xt/tenant-b/.htpasswd" > "$xt/tenant-a/auth/.htaccess"
chown 1001:1001 "$xt/tenant-a/auth" "$xt/tenant-a/auth/.htaccess" \
                 "$xt/tenant-a/auth/page.html"
chown 1002:1002 "$xt/tenant-b/.htpasswd"
chmod 644 "$xt/tenant-b/.htpasswd"
status_auth=$(curl -s -o /dev/null -w "%{http_code}" -u buser:bpass \
    "${BASE_URL}/tenant-a/auth/page.html")

# 5. same-tenant auth file still works
mkdir -p "$xt/tenant-a/auth-ok"
printf 'auth ok\n' > "$xt/tenant-a/auth-ok/page.html"
htpasswd -bcm "$xt/tenant-a/auth-ok/.htpasswd" auser apass >/dev/null 2>&1
printf 'AuthType Basic\nAuthName "T"\nAuthUserFile %s\nRequire valid-user\n' \
    "$xt/tenant-a/auth-ok/.htpasswd" > "$xt/tenant-a/auth-ok/.htaccess"
chown -R 1001:1001 "$xt/tenant-a/auth-ok"
status_ok=$(curl -s -o /dev/null -w "%{http_code}" -u auser:apass \
    "${BASE_URL}/tenant-a/auth-ok/page.html")

rm -rf "$xt"

if [ "$status_escape" = "403" ] && [ "$status_hard" = "500" ] \
   && [ "$status_sym" = "500" ] && [ "$status_auth" = "500" ] \
   && [ "$status_ok" = "200" ]; then
    pass
else
    fail "escape=$status_escape hard=$status_hard sym=$status_sym auth=$status_auth ok=$status_ok"
fi
