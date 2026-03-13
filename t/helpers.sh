#!/bin/bash
# Test helper functions for nginx htaccess module tests

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0
CURRENT_TEST=""

BASE_URL="http://127.0.0.1:8181"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Begin a named test
begin_test() {
    CURRENT_TEST="$1"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

# Pass current test
pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "  ${GREEN}PASS${NC} $CURRENT_TEST"
}

# Fail current test with message
fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "  ${RED}FAIL${NC} $CURRENT_TEST: $1"
}

# Assert HTTP status code
# Usage: assert_status GET /path 200
assert_status() {
    local method="$1"
    local path="$2"
    local expected="$3"
    shift 3
    local extra_args="$@"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" $extra_args "${BASE_URL}${path}")

    if [ "$status" = "$expected" ]; then
        pass
    else
        fail "expected status $expected, got $status"
    fi
}

# Assert HTTP status code with custom headers
# Usage: assert_status_with_header GET /path 200 "Header: value"
assert_status_with_header() {
    local method="$1"
    local path="$2"
    local expected="$3"
    local header="$4"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -H "$header" "${BASE_URL}${path}")

    if [ "$status" = "$expected" ]; then
        pass
    else
        fail "expected status $expected, got $status"
    fi
}

# Assert redirect (301/302/etc) to a specific location
# Usage: assert_redirect GET /old-path 301 /new-path
assert_redirect() {
    local method="$1"
    local path="$2"
    local expected_status="$3"
    local expected_location="$4"

    local response
    response=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" -X "$method" "${BASE_URL}${path}")
    local status=$(echo "$response" | awk '{print $1}')
    local location=$(echo "$response" | awk '{print $2}')

    if [ "$status" != "$expected_status" ]; then
        fail "expected status $expected_status, got $status"
        return
    fi

    # Check location - handle both absolute and relative
    if [ -n "$expected_location" ]; then
        if echo "$location" | grep -qF "$expected_location"; then
            pass
        else
            fail "expected redirect to $expected_location, got $location"
        fi
    else
        pass
    fi
}

# Assert response header exists with specific value
# Usage: assert_header GET /path "X-Custom" "value"
assert_header() {
    local method="$1"
    local path="$2"
    local header_name="$3"
    local expected_value="$4"

    local actual
    actual=$(curl -s -D - -o /dev/null -X "$method" "${BASE_URL}${path}" | \
        grep -i "^${header_name}:" | head -1 | sed 's/^[^:]*: *//' | tr -d '\r')

    if [ -z "$expected_value" ]; then
        # Just check header exists
        if [ -n "$actual" ]; then
            pass
        else
            fail "header $header_name not found"
        fi
    else
        if echo "$actual" | grep -qF "$expected_value"; then
            pass
        else
            fail "header $header_name expected '$expected_value', got '$actual'"
        fi
    fi
}

# Assert response header does NOT exist
# Usage: assert_no_header GET /path "X-Removed"
assert_no_header() {
    local method="$1"
    local path="$2"
    local header_name="$3"

    local actual
    actual=$(curl -s -D - -o /dev/null -X "$method" "${BASE_URL}${path}" | \
        grep -i "^${header_name}:" | head -1)

    if [ -z "$actual" ]; then
        pass
    else
        fail "header $header_name should not exist but found: $actual"
    fi
}

# Assert response body contains string
# Usage: assert_body_contains GET /path "expected text"
assert_body_contains() {
    local method="$1"
    local path="$2"
    local expected="$3"

    local body
    body=$(curl -s -X "$method" "${BASE_URL}${path}")

    if echo "$body" | grep -qF "$expected"; then
        pass
    else
        fail "body does not contain '$expected'"
    fi
}

# Assert Content-Type header
# Usage: assert_content_type GET /path "text/html"
assert_content_type() {
    local method="$1"
    local path="$2"
    local expected="$3"

    assert_header "$method" "$path" "Content-Type" "$expected"
}

# Assert no errors in nginx error log for a specific request
# Usage: assert_no_errors /path
assert_no_errors() {
    local path="$1"
    local log_file="${NGINX_ERROR_LOG:-/usr/local/nginx/logs/error.log}"

    # Make request
    curl -s -o /dev/null "${BASE_URL}${path}"

    # Check for htaccess errors (not warnings)
    if grep -q "htaccess:.*error\|htaccess.*\[emerg\]\|htaccess.*\[crit\]" "$log_file" 2>/dev/null; then
        fail "nginx error log contains htaccess errors"
    else
        pass
    fi
}

# Assert Basic auth is required (returns 401 without credentials)
# Usage: assert_auth_required GET /protected/
assert_auth_required() {
    local method="$1"
    local path="$2"

    assert_status "$method" "$path" 401
}

# Assert Basic auth succeeds with credentials
# Usage: assert_auth_ok GET /protected/ user password
assert_auth_ok() {
    local method="$1"
    local path="$2"
    local user="$3"
    local pass="$4"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -u "${user}:${pass}" "${BASE_URL}${path}")

    if [ "$status" = "200" ] || [ "$status" = "301" ] || [ "$status" = "302" ]; then
        pass
    else
        fail "auth expected success, got status $status"
    fi
}

# Assert Basic auth fails with wrong credentials
# Usage: assert_auth_fail GET /protected/ user wrongpass
assert_auth_fail() {
    local method="$1"
    local path="$2"
    local user="$3"
    local pass="$4"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -u "${user}:${pass}" "${BASE_URL}${path}")

    if [ "$status" = "401" ]; then
        pass
    else
        fail "auth expected 401, got status $status"
    fi
}

# Print test summary
print_summary() {
    echo ""
    echo "=================================="
    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}All $TESTS_TOTAL tests passed${NC}"
    else
        echo -e "${RED}$TESTS_FAILED of $TESTS_TOTAL tests failed${NC}"
        echo -e "${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
    fi
    echo "=================================="
    return $TESTS_FAILED
}
