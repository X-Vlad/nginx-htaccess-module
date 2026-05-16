#!/bin/bash
# Test: Satisfy Any / Satisfy All

# /satisfy/by-ip: Satisfy Any with auth + IP allowlist.
# From 127.0.0.1 (the test runner) the IP allow should be enough, even
# without credentials.
begin_test "Satisfy Any: localhost passes by IP, no credentials needed"
assert_status GET /satisfy/by-ip/page.html 200

begin_test "Satisfy Any: localhost still works with valid creds"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "testuser:testpass" "${BASE_URL}/satisfy/by-ip/page.html")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"

# /satisfy/strict: default Satisfy All - both auth AND IP required.
# Localhost passes IP, but no credentials = 401.
begin_test "Satisfy All (default): IP pass alone is NOT enough -> 401"
assert_status GET /satisfy/strict/page.html 401

begin_test "Satisfy All (default): IP + valid creds = 200"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "testuser:testpass" "${BASE_URL}/satisfy/strict/page.html")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"
