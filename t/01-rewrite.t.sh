#!/bin/bash
# Test: RewriteEngine, RewriteRule, RewriteCond

begin_test "RewriteRule basic rewrite"
assert_status GET /rewrite/simple 200

begin_test "RewriteRule with backreference"
assert_status GET /rewrite/page/42 200

begin_test "RewriteRule case-insensitive [NC]"
assert_status GET /rewrite/UPPER 200

begin_test "RewriteRule case-insensitive lowercase"
assert_status GET /rewrite/upper 200

begin_test "RewriteRule redirect 301 [R=301]"
assert_redirect GET /rewrite/old-url 301 /rewrite/target.html

begin_test "RewriteRule redirect 302 [R=302]"
assert_redirect GET /rewrite/temp-url 302 /rewrite/target.html

begin_test "RewriteRule forbidden [F]"
assert_status GET /rewrite/forbidden 403

begin_test "RewriteRule gone [G]"
assert_status GET /rewrite/gone 410

begin_test "RewriteRule QSA flag"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/rewrite/qsa-test?foo=bar")
if [ "$status" = "200" ]; then
    pass
else
    fail "expected 200, got $status"
fi

begin_test "RewriteRule QSD flag strips query"
assert_status GET "/rewrite/qsd-test?remove=this" 200

begin_test "RewriteCond HTTP_HOST match"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: test.example.com" "http://127.0.0.1:8181/rewrite/cond-host")
if [ "$status" = "302" ]; then
    pass
else
    fail "expected 302 (redirect on match), got $status"
fi

begin_test "RewriteCond HTTP_HOST no match"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: other.example.com" "http://127.0.0.1:8181/rewrite/cond-host")
if [ "$status" = "200" ]; then
    pass
else
    fail "expected 200 (no redirect, catch-all rewrite), got $status"
fi

begin_test "RewriteCond REQUEST_URI match"
assert_status GET /rewrite/cond-uri 200

begin_test "RewriteCond negation (!)"
assert_status GET /rewrite/negate-test 200

begin_test "RewriteCond -f (file not exists → rewrite)"
assert_status GET /rewrite/nonexistent-page 200
