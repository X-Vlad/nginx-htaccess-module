#!/bin/bash
# Test: Order/Allow/Deny, Require

begin_test "Require all granted"
assert_status GET /access/allowed.html 200

begin_test "Require all denied"
assert_status GET /access/denied/ 403

begin_test "Order Deny,Allow - localhost allowed"
assert_status GET /access/order-deny-allow/ 200

begin_test "Order Allow,Deny - localhost allowed"
assert_status GET /access/order-allow-deny/ 200
