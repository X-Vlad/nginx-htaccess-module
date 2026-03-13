#!/bin/bash
# Test: Header set/unset/append/add/merge, ForceType, AddType, AddDefaultCharset

begin_test "Header set X-Custom-Header"
assert_header GET /headers/test.html "X-Custom-Header" "test-value"

begin_test "Header set X-Powered-By"
assert_header GET /headers/test.html "X-Powered-By" "htaccess-module"

begin_test "AddDefaultCharset UTF-8 on text/html"
assert_header GET /headers/test.html "Content-Type" "charset"

begin_test "AddType text/css for .css"
assert_content_type GET /headers/style.css "text/css"
