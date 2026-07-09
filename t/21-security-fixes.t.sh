#!/bin/bash
# Test: security hardening - closes fail-open holes.
# Client address in the test harness is 127.0.0.1.

# --- standalone "Require ip" must deny non-matching clients ---
begin_test "Require ip: non-matching client denied"
assert_status GET /sec/reqip-deny/page.html 403

begin_test "Require ip: matching client (127.0.0.1) allowed"
assert_status GET /sec/reqip-allow/page.html 200

# --- "Require all granted" must not override an explicit Deny ---
begin_test "Require all granted + Deny from client -> denied"
assert_status GET /sec/granted-deny/page.html 403

# --- AuthType Digest (unsupported) must fail closed ---
begin_test "AuthType Digest fails closed (500), not public"
assert_status GET /sec/digest/page.html 500

# --- Require without a usable AuthType must fail closed ---
begin_test "Require valid-user without AuthType -> 500"
assert_status GET /sec/req-noauth/page.html 500

# --- <Limit GET> also constrains HEAD (no method bypass) ---
begin_test "<Limit GET> Deny: GET blocked"
assert_status GET /sec/limit-head/page.html 403

begin_test "<Limit GET> Deny: HEAD also blocked (no bypass)"
assert_status HEAD /sec/limit-head/page.html 403 -I

# --- RewriteRule '- [R=404]' returns the status (hide-file idiom) ---
begin_test "RewriteRule - [R=404] returns 404"
assert_status GET /sec/hide/secret.txt 404

begin_test "R=404: non-matching request still served"
assert_status GET /sec/hide/page.html 200

# --- <Files ~ "regex"> tilde form is a real regex match ---
begin_test "<Files ~ regex> Deny matches target"
assert_status GET /sec/tilde/foo.secret 403

begin_test "<Files ~ regex> non-matching file served"
assert_status GET /sec/tilde/page.html 200

# --- backup .ht* files are blocked, not just the 4 canonical names ---
begin_test "backup .htpasswd.bak blocked"
assert_status GET /.htpasswd.bak 403

begin_test "backup .htaccess.save blocked"
assert_status GET /sec/tilde/.htaccess.save 403

# --- Options -Indexes suppresses directory listing (autoindex on) ---
begin_test "Options -Indexes: listing refused"
assert_status GET /sec/listing/blocked/ 403

begin_test "control: dir without -Indexes still lists (autoindex)"
assert_status GET /sec/listing/open/ 200

# --- php_flag engine off blocks script execution ---
begin_test "php_flag engine off: .php blocked"
assert_status GET /sec/noexec/shell.php 403

begin_test "engine off: non-script still served"
assert_status GET /sec/noexec/ok.txt 200

# --- <FilesMatch> SetHandler none blocks script execution ---
begin_test "SetHandler none: matching .php blocked"
assert_status GET /sec/nohandler/evil.php 403

# --- <Files> Require enforced with inherited AuthType (no bypass) ---
# Top-level "AuthType Basic"; <Files locked.html> narrows to "Require user
# testuser". A different valid htpasswd user must NOT reach locked.html.
begin_test "<Files> Require user: wrong valid user rejected (no bypass)"
assert_status GET /sec/inherit/locked.html 401 -u otheruser:otherpass

begin_test "<Files> Require user: correct user allowed"
assert_status GET /sec/inherit/locked.html 200 -u testuser:testpass

begin_test "non-matching file: top-level auth still applies"
assert_status GET /sec/inherit/open.html 200 -u otheruser:otherpass

# --- Satisfy Any must also waive per-block auth when IP already granted ---
# (regression guard: block Require must not challenge an IP-satisfied client)
begin_test "Satisfy Any + IP allow: <Limit> Require not challenged"
assert_status GET /sec/satisfy-block/page.html 200
