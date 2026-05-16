#!/bin/bash
# Test: <Limit> / <LimitExcept> blocks

# --- <Limit POST PUT> requires auth, GET stays open ---

begin_test "Limit POST PUT - GET is unrestricted (no auth)"
assert_status GET /limit/post-auth/page.html 200

begin_test "Limit POST PUT - POST without creds → 401"
assert_status POST /limit/post-auth/page.html 401

begin_test "Limit POST PUT - POST with creds → not 401 (auth check passes)"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u "testuser:testpass" "${BASE_URL}/limit/post-auth/page.html")
if [ "$status" != "401" ] && [ "$status" != "403" ]; then
    pass
else
    fail "expected non-401/403 (got $status); auth should have passed"
fi

begin_test "Limit POST PUT - PUT without creds → 401"
assert_status PUT /limit/post-auth/page.html 401

# --- <LimitExcept GET HEAD> denies everything else ---

begin_test "LimitExcept GET HEAD - GET allowed"
assert_status GET /limit/get-only/page.html 200

begin_test "LimitExcept GET HEAD - POST denied"
assert_status POST /limit/get-only/page.html 403

begin_test "LimitExcept GET HEAD - DELETE denied"
assert_status DELETE /limit/get-only/page.html 403
