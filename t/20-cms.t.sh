#!/bin/bash
# Test: CMS compatibility - verify real .htaccess files parse without errors

NGINX_ERROR_LOG="${NGINX_PREFIX:-/usr/local/nginx}/logs/error.log"

# Clear error log before CMS tests
> "$NGINX_ERROR_LOG" 2>/dev/null || true

CMS_LIST="wordpress laravel joomla drupal magento opencart prestashop codeigniter dle modx"

for cms in $CMS_LIST; do
    begin_test "CMS $cms - .htaccess parses without error"

    # Make a request to trigger .htaccess parsing
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/$cms/")

    # Check for parse errors (emerg/crit/alert level)
    if grep -qi "htaccess.*\(emerg\|crit\|alert\)" "$NGINX_ERROR_LOG" 2>/dev/null; then
        fail "parse errors in nginx error log for $cms"
    else
        pass
    fi

    # Clear for next CMS
    > "$NGINX_ERROR_LOG" 2>/dev/null || true
done

for cms in $CMS_LIST; do
    begin_test "CMS $cms - no 500 error"

    status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/$cms/")

    if [ "$status" = "500" ]; then
        fail "got 500 Internal Server Error"
    else
        pass
    fi
done

# WordPress-specific: test pretty permalink pattern
begin_test "CMS WordPress - pretty permalink rewrite"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/wordpress/sample-post")
# Should not be 500 (should be 200 from index.php rewrite, or 404 if index.php doesn't handle it)
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi

# Laravel-specific: trailing slash redirect
begin_test "CMS Laravel - front controller rewrite"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/laravel/some/route")
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi

# Joomla-specific: SEF URL
begin_test "CMS Joomla - SEF URL rewrite"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/joomla/component/content")
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi

# OpenCart-specific: SEO URL with QSA
begin_test "CMS OpenCart - SEO URL rewrite"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/opencart/product/laptop")
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi

# DLE-specific: article URL
begin_test "CMS DLE - article URL rewrite"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/dle/123-test-article.html")
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi

# MODX-specific: friendly URL
begin_test "CMS MODX - friendly URL rewrite"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/modx/about/team")
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi

# PrestaShop-specific: product image URL
begin_test "CMS PrestaShop - rewrite rules parse"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/prestashop/")
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi

# Magento-specific: rewrites
begin_test "CMS Magento - rewrite rules parse"
status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8181/cms/magento/catalog/product/view")
if [ "$status" = "500" ]; then
    fail "got 500"
else
    pass
fi
