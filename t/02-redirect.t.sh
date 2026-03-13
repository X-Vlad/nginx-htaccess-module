#!/bin/bash
# Test: Redirect, RedirectMatch, RedirectPermanent, RedirectTemp

begin_test "Redirect 301"
assert_redirect GET /redirect/old-page 301 /redirect/target.html

begin_test "Redirect 302"
assert_redirect GET /redirect/temp-page 302 /redirect/target.html

begin_test "RedirectPermanent (301)"
assert_redirect GET /redirect/perm-page 301 /redirect/target.html

begin_test "RedirectTemp (302)"
assert_redirect GET /redirect/temp-page2 302 /redirect/target.html

begin_test "Redirect gone (410)"
assert_status GET /redirect/deleted-page 410

begin_test "RedirectMatch with backreference"
assert_redirect GET /redirect/article/123 301 /redirect/target.html
