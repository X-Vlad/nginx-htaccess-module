#!/bin/bash
# Test: Security - direct access to .htaccess/.htpasswd/.htdigest blocked

begin_test "Direct access to .htaccess → 403"
assert_status GET /security/.htaccess 403

begin_test "Direct access to .htpasswd → 403"
assert_status GET /security/.htpasswd 403

begin_test "Direct access to .htdigest → 403"
assert_status GET /security/.htdigest 403

begin_test "Normal file in same directory → 200"
assert_status GET /security/normal.html 200

begin_test "Root .htaccess → 403"
assert_status GET /.htaccess 403
