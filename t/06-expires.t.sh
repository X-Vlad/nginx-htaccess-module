#!/bin/bash
# Test: ExpiresActive, ExpiresDefault, ExpiresByType

begin_test "Expires active - Cache-Control header present"
assert_header GET /expires/page.html "Cache-Control" "max-age="

begin_test "Expires active - Expires header present"
assert_header GET /expires/page.html "Expires" ""

begin_test "ExpiresByType text/css"
assert_header GET /expires/style.css "Cache-Control" "max-age="

begin_test "ExpiresByType application/javascript"
assert_header GET /expires/script.js "Cache-Control" "max-age="
