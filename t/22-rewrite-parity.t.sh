#!/bin/bash
# Test: mod_rewrite / mod_headers / mod_dir Apache-parity features.

# --- %{HTTP:Header} expansion in RewriteCond ---
begin_test "%{HTTP:X-Route} matches -> redirect"
assert_status_with_header GET /sec/vars/page.html 302 "X-Route: admin"

begin_test "%{HTTP:X-Route} absent -> no redirect (served)"
assert_status GET /sec/vars/page.html 200

# --- REQUEST_SCHEME expansion (was empty -> now http/https) ---
begin_test "REQUEST_SCHEME resolves to http -> redirect"
assert_redirect GET /sec/scheme/page.html 302 /is-http

# --- %1-%9 RewriteCond backreferences (www canonicalization) ---
begin_test "%1 cond backref expands captured host part"
loc=$(curl -s -o /dev/null -D - -H "Host: www.foo.com" \
      "${BASE_URL}/sec/wwwcanon/page.html" | grep -i '^location:' \
      | tr -d '\r' | sed 's/^[Ll]ocation:[ ]*//')
if echo "$loc" | grep -q "foo.com/canonical"; then pass; else fail "Location=[$loc]"; fi

begin_test "no www -> cond fails, no redirect"
assert_status_with_header GET /sec/wwwcanon/page.html 200 "Host: foo.com"

# --- $N from the rule pattern usable in RewriteCond test strings ---
begin_test "\$1 in RewriteCond matches -> redirect"
assert_redirect GET /sec/dollarcond/secret.html 302 /found

begin_test "\$1 in RewriteCond no match -> served"
assert_status GET /sec/dollarcond/other.html 200

# --- RewriteCond lexicographic operator (=), the force-HTTPS class ---
begin_test "RewriteCond =GET matches -> redirect"
assert_redirect GET /sec/eqtest/page.html 302 /is-get

# --- original query string carried through an external redirect ---
begin_test "redirect preserves ?query"
assert_redirect GET "/sec/qs/page.html?x=5" 302 /dest?x=5

# --- long-form RewriteRule flag [forbidden] must block (was fail-open) ---
begin_test "long-form [forbidden] flag blocks matching file"
assert_status GET /sec/forbidden/data.secret 403

begin_test "long-form [forbidden]: non-matching file served"
assert_status GET /sec/forbidden/page.html 200

# --- FallbackResource front controller ---
begin_test "FallbackResource: missing file -> front controller body"
assert_body_contains GET /sec/fallback/no-such-route "FALLBACK-APP"

begin_test "FallbackResource: existing file served as-is"
assert_body_contains GET /sec/fallback/exists.html "EXISTS-REAL"

# --- %{SCRIPT_FILENAME} resolves for -f test ---
begin_test "%{SCRIPT_FILENAME} -f resolves to real path"
assert_redirect GET /sec/scriptfn/real.html 302 /exists

# --- conditional Header env= (SetEnvIf-gated CORS) ---
begin_test "Header env=VAR: applied when env set"
h=$(curl -s -o /dev/null -D - -H "User-Agent: CorsClient" \
      "${BASE_URL}/sec/cors/page.html" | grep -i '^x-cors:' | tr -d '\r')
if [ -n "$h" ]; then pass; else fail "X-CORS header missing when env set"; fi

begin_test "Header env=VAR: skipped when env unset"
h=$(curl -s -o /dev/null -D - -H "User-Agent: Other" \
      "${BASE_URL}/sec/cors/page.html" | grep -i '^x-cors:' | tr -d '\r')
if [ -z "$h" ]; then pass; else fail "X-CORS header present when env unset: $h"; fi

# --- <RequireNone> denies matching clients (was fail-open inversion) ---
begin_test "<RequireNone> Require ip: matching client denied"
assert_status GET /sec/reqnone/page.html 403

begin_test "<RequireNone> Require ip: non-matching client allowed"
assert_status GET /sec/reqnone-ok/page.html 200
