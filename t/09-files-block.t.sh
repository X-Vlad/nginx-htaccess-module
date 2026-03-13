#!/bin/bash
# Test: <Files> and <FilesMatch> blocks

begin_test "Files block - secret.txt denied"
assert_status GET /files-block/secret.txt 403

begin_test "Files block - public.txt allowed"
assert_status GET /files-block/public.txt 200

begin_test "FilesMatch - XML header applied"
assert_header GET /files-block/data.xml "X-File-Type" "xml-matched"
