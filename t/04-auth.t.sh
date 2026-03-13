#!/bin/bash
# Test: Basic Authentication

begin_test "Auth required (no credentials → 401)"
assert_status GET /auth/protected.html 401

begin_test "Auth with correct credentials"
assert_auth_ok GET /auth/protected.html testuser testpass

begin_test "Auth with wrong password"
assert_auth_fail GET /auth/protected.html testuser wrongpass

begin_test "Auth with wrong username"
assert_auth_fail GET /auth/protected.html wronguser testpass

begin_test "Auth WWW-Authenticate header present"
assert_header GET /auth/protected.html "WWW-Authenticate" "Basic realm="
