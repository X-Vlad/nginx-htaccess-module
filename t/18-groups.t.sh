#!/bin/bash
# Test: AuthGroupFile + Require group
#
# /groups/.htgroup contains:
#   admins: testuser
#   users:  testuser otheruser
#
# /groups/.htaccess requires "Require group admins".

begin_test "Require group admins: testuser is a member -> 200"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "testuser:testpass" "${BASE_URL}/groups/page.html")
[ "$status" = "200" ] && pass || fail "expected 200, got $status"

begin_test "Require group admins: otheruser is NOT a member -> 401"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "otheruser:otherpass" "${BASE_URL}/groups/page.html")
[ "$status" = "401" ] && pass || fail "expected 401, got $status"

begin_test "Require group: missing credentials -> 401"
assert_status GET /groups/page.html 401

# Regression: <Files> + Require group must be enforced, not silently dropped.
begin_test "<Files> + Require group: admins member allowed"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "testuser:testpass" "${BASE_URL}/groups/files-secret.html")
[ "$status" = "200" ] || [ "$status" = "404" ] && pass || \
    fail "expected 200 or 404, got $status"

begin_test "<Files> + Require group: non-member rejected (no bypass)"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "otheruser:otherpass" "${BASE_URL}/groups/files-secret.html")
[ "$status" = "401" ] && pass || \
    fail "AUTH BYPASS: otheruser passed <Files> Require group admins (got $status)"
