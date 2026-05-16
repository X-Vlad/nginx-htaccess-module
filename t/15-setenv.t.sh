#!/bin/bash
# Test: SetEnv (unconditional) / SetEnvIfNoCase / BrowserMatch / BrowserMatchNoCase
#
# /setenv/.htaccess defines:
#   SetEnv             SITE_FLAVOR  classic
#   SetEnvIf           User-Agent   ^TestBot    IS_BOT=yes
#   SetEnvIfNoCase     User-Agent   ^testbot    IS_BOT_NC=yes
#   BrowserMatch       ^Mozilla     IS_MOZ=yes
#   BrowserMatchNoCase ^MOZILLA     IS_MOZ_NC=yes
#
# nginx.conf surfaces the resulting variables as X-... response headers
# on every /setenv/ request via add_header.

URL="${BASE_URL}/setenv/page.html"

# --- SetEnv: unconditional ---
begin_test "SetEnv: unconditional value set on every request"
assert_header GET /setenv/page.html "X-Site-Flavor" "classic"

# --- SetEnvIf: regex matches exactly ---
begin_test "SetEnvIf User-Agent ^TestBot - case-sensitive match"
val=$(curl -s -D - -o /dev/null -A "TestBot/1.0" "$URL" | \
    grep -i '^X-Is-Bot:' | sed 's/^[^:]*: *//' | tr -d '\r')
[ "$val" = "yes" ] && pass || fail "expected yes, got '$val'"

begin_test "SetEnvIf User-Agent ^TestBot - case mismatch does NOT match"
val=$(curl -s -D - -o /dev/null -A "testbot/1.0" "$URL" | \
    grep -i '^X-Is-Bot:' | sed 's/^[^:]*: *//' | tr -d '\r')
[ -z "$val" ] && pass || fail "expected empty, got '$val'"

# --- SetEnvIfNoCase: case-insensitive ---
begin_test "SetEnvIfNoCase - lowercase UA still matches"
val=$(curl -s -D - -o /dev/null -A "testbot/1.0" "$URL" | \
    grep -i '^X-Is-Bot-Nc:' | sed 's/^[^:]*: *//' | tr -d '\r')
[ "$val" = "yes" ] && pass || fail "expected yes, got '$val'"

# --- BrowserMatch: shorthand for SetEnvIf User-Agent ---
begin_test "BrowserMatch ^Mozilla - matches Mozilla/5.0"
val=$(curl -s -D - -o /dev/null -A "Mozilla/5.0" "$URL" | \
    grep -i '^X-Is-Moz:' | sed 's/^[^:]*: *//' | tr -d '\r')
[ "$val" = "yes" ] && pass || fail "expected yes, got '$val'"

begin_test "BrowserMatch ^Mozilla - case mismatch does NOT match"
val=$(curl -s -D - -o /dev/null -A "mozilla/5.0" "$URL" | \
    grep -i '^X-Is-Moz:' | sed 's/^[^:]*: *//' | tr -d '\r')
[ -z "$val" ] && pass || fail "expected empty, got '$val'"

begin_test "BrowserMatchNoCase ^MOZILLA - matches any case"
val=$(curl -s -D - -o /dev/null -A "Mozilla/5.0" "$URL" | \
    grep -i '^X-Is-Moz-Nc:' | sed 's/^[^:]*: *//' | tr -d '\r')
[ "$val" = "yes" ] && pass || fail "expected yes, got '$val'"
