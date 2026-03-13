#!/bin/bash
# Test: DirectoryIndex

begin_test "DirectoryIndex serves index.html"
assert_status GET /dirindex/ 200

begin_test "DirectoryIndex body contains content"
assert_body_contains GET /dirindex/ "index.html"
