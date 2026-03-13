#!/bin/bash
# Test: ErrorDocument

begin_test "ErrorDocument 404 custom page"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/errordoc/nonexistent")
if [ "$status" = "404" ]; then
    pass
else
    fail "expected 404, got $status"
fi

begin_test "Normal file still returns 200"
assert_status GET /errordoc/page.html 200
