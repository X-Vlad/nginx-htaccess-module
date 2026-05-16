#!/bin/bash
# Test: php_value / php_admin_value / php_flag / php_admin_flag
#
# The nginx test config registers a regex location "/<dir>/__pv" that echoes
# both $htaccess_php_value and $htaccess_php_admin_value into the body
# (between <<...>> markers). HTTP response headers can't carry the embedded
# newline separator that PHP_VALUE expects, so we inspect the body instead.

dump=$(curl -s "${BASE_URL}/php-values/__pv")

begin_test "php_value - upload_max_filesize collected"
if echo "$dump" | grep -q "upload_max_filesize=64M"; then pass
else fail "missing upload_max_filesize in: $dump"; fi

begin_test "php_value - post_max_size collected"
if echo "$dump" | grep -q "post_max_size=128M"; then pass
else fail "missing post_max_size in: $dump"; fi

begin_test "php_flag - display_errors collected"
if echo "$dump" | grep -q "display_errors=off"; then pass
else fail "missing display_errors in: $dump"; fi

begin_test "php_admin_value - memory_limit collected"
if echo "$dump" | grep -q "memory_limit=256M"; then pass
else fail "missing memory_limit in: $dump"; fi

begin_test "php_admin_flag - log_errors collected"
if echo "$dump" | grep -q "log_errors=on"; then pass
else fail "missing log_errors in: $dump"; fi

# Separate sections, separate variables: extract just the PV<<...>> block
# and check no admin-only entries appear there.
pv_block=$(echo "$dump" | awk '/^PV<</,/>>$/')
pav_block=$(echo "$dump" | awk '/^PAV<</,/>>$/')

begin_test "php_admin_value does not leak into PHP_VALUE"
if echo "$pv_block" | grep -q "memory_limit"; then
    fail "memory_limit leaked into PHP_VALUE"
else pass; fi

begin_test "php_value does not leak into PHP_ADMIN_VALUE"
if echo "$pav_block" | grep -q "upload_max_filesize"; then
    fail "upload_max_filesize leaked into PHP_ADMIN_VALUE"
else pass; fi

# When no php_value directives exist, the variable must be empty.
begin_test "Variables empty for path without php_value directives"
empty_dump=$(curl -s "${BASE_URL}/access/__pv")
if [ "$empty_dump" = "PV<<>>"$'\n'"PAV<<>>" ]; then
    pass
else
    fail "expected empty markers, got: $empty_dump"
fi
