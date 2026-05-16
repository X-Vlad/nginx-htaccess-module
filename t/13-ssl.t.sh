#!/bin/bash
# Test: SSLRequireSSL

begin_test "SSLRequireSSL - plain HTTP request → 403"
assert_status GET /ssl-required/page.html 403

begin_test "SSLRequireSSL - X-Forwarded-Proto: https → 200"
assert_status_with_header GET /ssl-required/page.html 200 \
    "X-Forwarded-Proto: https"

begin_test "SSLRequireSSL - X-Forwarded-Proto: http → 403"
assert_status_with_header GET /ssl-required/page.html 403 \
    "X-Forwarded-Proto: http"
