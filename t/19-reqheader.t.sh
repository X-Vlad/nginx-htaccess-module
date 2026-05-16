#!/bin/bash
# Test: RequestHeader (modifies r->headers_in before upstream sees them)
#
# /reqheader/.htaccess:
#   RequestHeader set   X-Injected      "from-htaccess"
#   RequestHeader set   X-Forwarded-Proto "https"
#   RequestHeader unset X-Drop-Me
#   RequestHeader add   X-Multi         "one"
#   RequestHeader add   X-Multi         "two"

begin_test "RequestHeader set: adds header not sent by client"
out=$(curl -s "${BASE_URL}/reqheader/__req")
echo "$out" | grep -q "INJECTED=\[from-htaccess\]" && pass || \
    fail "expected INJECTED=[from-htaccess], got: $out"

begin_test "RequestHeader set: overwrites client-sent value"
out=$(curl -s -H "X-Forwarded-Proto: http" "${BASE_URL}/reqheader/__req")
echo "$out" | grep -q "XFWD=\[https\]" && pass || \
    fail "expected XFWD=[https], got: $out"

begin_test "RequestHeader set: header name lookup is case-insensitive (lowercase)"
out=$(curl -s -H "x-forwarded-proto: http" "${BASE_URL}/reqheader/__req")
echo "$out" | grep -q "XFWD=\[https\]" && pass || \
    fail "expected XFWD=[https] with lowercase client header, got: $out"

begin_test "RequestHeader unset: removes client-sent header"
out=$(curl -s -H "X-Drop-Me: please-drop" "${BASE_URL}/reqheader/__req")
echo "$out" | grep -q "DROPME=\[\]" && pass || \
    fail "expected DROPME=[], got: $out"

begin_test "RequestHeader unset: also works with case-mismatched client header"
out=$(curl -s -H "x-drop-me: please-drop" "${BASE_URL}/reqheader/__req")
echo "$out" | grep -q "DROPME=\[\]" && pass || \
    fail "expected DROPME=[] (case-insensitive unset), got: $out"

begin_test "RequestHeader add: multiple values appear in joined form"
out=$(curl -s "${BASE_URL}/reqheader/__req")
# nginx joins multiple same-name headers with ", " when read via $http_
echo "$out" | grep -q "MULTI=\[one, two\]" && pass || \
    fail "expected MULTI=[one, two], got: $out"
