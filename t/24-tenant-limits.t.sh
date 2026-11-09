#!/bin/bash
# Regression tests for the tenant-limits pass (third audit, 2026-11-08):
# regex CPU budget, control characters, RequestHeader Host, env allow list.
# Fixtures are generated here and removed at the end.

L="${HTDOCS_ROOT}/sec/limits"
rm -rf "$L"
mkdir -p "$L"

mkfix() { # dir, .htaccess content
    mkdir -p "$L/$1"
    printf '%b' "$2" > "$L/$1/.htaccess"
    printf 'page\n' > "$L/$1/page.html"
}

# P-2: 1023 conditions that each stay just under the per-match limit must not
# keep a worker busy: the per-request budget ends the request with 500.
{
    echo 'RewriteEngine On'
    for b in $(seq 31); do
        for i in $(seq 32); do echo 'RewriteCond %{REQUEST_URI} (a|aa)+$ [OR]'; done
        echo 'RewriteRule ^ - [F]'
    done
} > /tmp/hta-budget.$$
mkfix budget ''
mv /tmp/hta-budget.$$ "$L/budget/.htaccess"

begin_test "regex budget per request ends a near-limit flood with 500 quickly"
out=$(curl -s -m 30 -o /dev/null -w '%{http_code} %{time_total}' \
    "${BASE_URL}/sec/limits/budget/$(printf 'a%.0s' $(seq 20))b")
code=${out% *}; t=${out#* }
if [ "$code" = "500" ] && awk -v t="$t" 'BEGIN { exit !(t < 1.0) }'; then
    pass
else
    fail "expected 500 within 1s, got $out"
fi

begin_test "a match over the per-match limit answers 500, not an empty reply"
out=$(curl -s -m 30 -o /dev/null -w '%{http_code}' \
    "${BASE_URL}/sec/limits/budget/$(printf 'a%.0s' $(seq 40))b")
if [ "$out" = "500" ]; then pass; else fail "got $out"; fi

begin_test "regex budget overrun is logged"
if grep -q 'htaccess: request budget' "${NGINX_PREFIX}/logs/error.log"; then
    pass
else
    fail "no budget line in error.log"
fi

# P-2: more than 1024 patterns in one file are refused at parse time.
{
    echo 'RewriteEngine On'
    for i in $(seq 1100); do echo "RewriteRule ^nomatch$i\$ - [F]"; done
} > /tmp/hta-cap.$$
mkfix cap ''
mv /tmp/hta-cap.$$ "$L/cap/.htaccess"
begin_test "more than 1024 regexes in one file fail closed"
assert_status GET /sec/limits/cap/page.html 500

# Control characters other than CR/LF/NUL must not reach Location either.
mkfix ctl 'RewriteEngine On\nRewriteRule ^go$ http://example.test/%{HTTP:X-In} [R=302,L]\n'
begin_test "VT from a request header does not reach Location"
headers=$(curl -s -D - -o /dev/null -H $'X-In: a\x0bb' "${BASE_URL}/sec/limits/ctl/go")
if printf '%s' "$headers" | grep -q $'\x0b'; then
    fail "control character in response headers"
else
    pass
fi

# RequestHeader must not add a second Host header.
mkfix host 'RequestHeader set Host evil.test\n'
begin_test "RequestHeader set Host is refused"
body=$(curl -s "${BASE_URL}/sec/limits/host/__req")
if printf '%s' "$body" | grep -q 'HOST=\[127.0.0.1:8181\]'; then
    pass
else
    fail "Host changed: $body"
fi

# Env allow list: an operator variable not in htaccess_env_allow stays as set.
mkdir -p "$L/envguard"
printf 'page\n' > "$L/envguard/page.html"
printf 'SetEnv guard forged\nSetEnv allowed yes\n' > "$L/envguard/.htaccess"
begin_test "SetEnv writes only variables in htaccess_env_allow"
h=$(curl -s -D - -o /dev/null "${BASE_URL}/sec/limits/envguard/page.html")
if printf '%s' "$h" | grep -qi '^X-Guard: \[orig\]' \
   && printf '%s' "$h" | grep -qi '^X-Allowed: \[yes\]'; then
    pass
else
    fail "$h"
fi

printf 'UnsetEnv guard\n' > "$L/envguard/.htaccess"
begin_test "UnsetEnv cannot clear an operator variable"
h=$(curl -s -D - -o /dev/null "${BASE_URL}/sec/limits/envguard/page.html")
if printf '%s' "$h" | grep -qi '^X-Guard: \[orig\]'; then pass; else fail "$h"; fi

printf 'RewriteEngine On\nRewriteRule ^page\\.html$ - [E=guard:forged]\n' > "$L/envguard/.htaccess"
begin_test "[E=] cannot write an operator variable"
h=$(curl -s -D - -o /dev/null "${BASE_URL}/sec/limits/envguard/page.html")
if printf '%s' "$h" | grep -qi '^X-Guard: \[orig\]'; then pass; else fail "$h"; fi

printf 'RewriteEngine On\nRewriteRule ^page\\.html$ - [E=remote_addr:6.6.6.6]\n' > "$L/envguard/.htaccess"
begin_test "[E=] cannot forge \$remote_addr"
h=$(curl -s -D - -o /dev/null "${BASE_URL}/sec/limits/envguard/page.html")
if printf '%s' "$h" | grep -qi '^X-RA: \[127.0.0.1\]'; then pass; else fail "$h"; fi

printf 'RewriteEngine On\nRewriteRule ^page\\.html$ - [E=allowed:viaflag]\n' > "$L/envguard/.htaccess"
begin_test "[E=] still writes an allowed variable"
h=$(curl -s -D - -o /dev/null "${BASE_URL}/sec/limits/envguard/page.html")
if printf '%s' "$h" | grep -qi '^X-Allowed: \[viaflag\]'; then pass; else fail "$h"; fi

# <Files ""> matches nothing; its rules must not silently vanish.
mkfix emptyfiles '<Files "">\nRequire all denied\n</Files>\n'
begin_test '<Files ""> fails closed'
assert_status GET /sec/limits/emptyfiles/page.html 500

# A refused AuthUserFile is logged with its path.
mkfix noauth 'AuthType Basic\nAuthName "x"\nAuthUserFile /nonexistent/.htpasswd\nRequire valid-user\n'
begin_test "missing AuthUserFile fails closed and is logged"
code=$(curl -s -o /dev/null -w '%{http_code}' -u u:p "${BASE_URL}/sec/limits/noauth/page.html")
if [ "$code" = "500" ] && grep -q 'AuthUserFile "/nonexistent/.htpasswd"' "${NGINX_PREFIX}/logs/error.log"; then
    pass
else
    fail "code $code, log: $(grep -c AuthUserFile "${NGINX_PREFIX}/logs/error.log")"
fi

# RewriteCond file tests resolve beneath the document root in one step
# (openat2 RESOLVE_BENEATH): a symlink inside the root still counts, one that
# leaves it behaves as missing.
mkfix ftest 'RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} -f\nRewriteRule ^(link-in|link-out)$ yes.html [L]\nRewriteRule ^(link-in|link-out)$ no.html [L]\n'
printf 'yes\n' > "$L/ftest/yes.html"
printf 'no\n' > "$L/ftest/no.html"
ln -s page.html "$L/ftest/link-in"
ln -s /etc/passwd "$L/ftest/link-out"
begin_test "-f follows a symlink that stays inside the root"
body=$(curl -s "${BASE_URL}/sec/limits/ftest/link-in")
if [ "$body" = "yes" ]; then pass; else fail "got: $body"; fi
begin_test "-f treats a symlink out of the root as missing"
body=$(curl -s "${BASE_URL}/sec/limits/ftest/link-out")
if [ "$body" = "no" ]; then pass; else fail "got: $body"; fi

# Long values must not drop out of a condition: a deny rule on the query
# string or User-Agent was skipped for any value over 4 KB.
mkfix longval 'RewriteEngine On\nRewriteCond %{QUERY_STRING} union.*select [NC]\nRewriteRule ^ - [F]\nRewriteCond %{HTTP_USER_AGENT} sqlmap [NC]\nRewriteRule ^ - [F]\n'
begin_test "a long query string does not slip past a RewriteCond deny"
long=$(printf 'a%.0s' $(seq 6000))
assert_status GET "/sec/limits/longval/page.html?id=1%20union%20select%201&p=$long" 403
begin_test "a long User-Agent does not slip past a RewriteCond deny"
code=$(curl -s -o /dev/null -w '%{http_code}' -A "sqlmap/1.8 $long" "${BASE_URL}/sec/limits/longval/page.html")
if [ "$code" = "403" ]; then pass; else fail "got $code"; fi

# php_value names: only [A-Za-z0-9_.]; tricks that PHP still reads as a
# dangerous setting are dropped.
mkfix phpname 'php_value "auto_prepend_file " /tmp/y\nphp_flag "auto_prepend_file=/tmp/z;" on\nphp_value "open_basedir\t" /\nphp_value memory_limit 128M\n'
begin_test "php_value names with spaces or INI syntax are dropped"
body=$(curl -s "${BASE_URL}/sec/limits/phpname/__pv")
if printf '%s' "$body" | grep -q 'auto_prepend\|open_basedir'; then
    fail "dangerous setting leaked: $body"
elif printf '%s' "$body" | grep -q 'memory_limit=128M'; then
    pass
else
    fail "valid setting lost: $body"
fi

# Memory budget: thousands of conditions expanding a long query string many
# times grew a worker by hundreds of MB per request.
python3 - "$L" <<'PY'
import os, sys
d = os.path.join(sys.argv[1], 'memflood'); os.makedirs(d, exist_ok=True)
q = '%{QUERY_STRING}' * 7
lines = ['RewriteEngine On']
for b in range(255):
    lines += ['RewriteCond %s =x' % q] * 32 + ['RewriteRule nomatch$ - [F]']
open(os.path.join(d, '.htaccess'), 'w').write('\n'.join(lines) + '\n')
d = os.path.join(sys.argv[1], 'ftflood'); os.makedirs(d, exist_ok=True)
lines = ['RewriteEngine On']
for b in range(255):
    lines += ['RewriteCond %%{DOCUMENT_ROOT}/missing%d -f [OR]' % i for i in range(32)] + ['RewriteRule nomatch$ - [F]']
open(os.path.join(d, '.htaccess'), 'w').write('\n'.join(lines) + '\n')
PY
begin_test "expansion memory budget ends a request that expands too much"
qs=$(printf 'a%.0s' $(seq 7000))
out=$(curl -s -m 30 -o /dev/null -w '%{http_code} %{time_total}' "${BASE_URL}/sec/limits/memflood/nomatch?$qs")
code=${out% *}; t=${out#* }
if [ "$code" = "500" ] && awk -v t="$t" 'BEGIN { exit !(t < 0.5) }'; then pass; else fail "got $out"; fi

begin_test "file tests share the request time budget"
out=$(curl -s -m 30 -o /dev/null -w '%{http_code} %{time_total}' "${BASE_URL}/sec/limits/ftflood/nomatch")
t=${out#* }
if awk -v t="$t" 'BEGIN { exit !(t < 0.5) }'; then pass; else fail "got $out"; fi

rm -rf "$L"
