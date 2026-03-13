#!/bin/bash
# Test: SetEnvIf

begin_test "SetEnvIf - HTML page accessible"
assert_status GET /setenvif/test.html 200

begin_test "SetEnvIf - page loads with custom User-Agent"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: TestBot" "http://127.0.0.1:8181/setenvif/test.html")
if [ "$status" = "200" ]; then
    pass
else
    fail "expected 200, got $status"
fi
