#!/bin/bash
# Cache eviction / UAF regression: > HTA_CACHE_SLOTS distinct .htaccess files,
# each request uses a parent and a child file.  Runs under ASan in CI.

begin_test "cache eviction with 1100 distinct .htaccess files"

base="${HTDOCS_ROOT}/sec/cache-evict"

rm -rf "$base"
mkdir -p "$base"
printf 'Header set X-Cache-Parent yes\n' > "$base/.htaccess"
printf 'cache page\n' > "$base/page.html"

i=1
while [ "$i" -le 1100 ]; do
    mkdir -p "$base/$i"
    printf 'Header set X-Cache-Child %s\n' "$i" > "$base/$i/.htaccess"
    printf 'cache page\n' > "$base/$i/page.html"
    i=$((i + 1))
done

failed=0
i=1
while [ "$i" -le 1100 ]; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${BASE_URL}/sec/cache-evict/$i/page.html")
    if [ "$status" != "200" ]; then
        failed=$((failed + 1))
        break
    fi
    i=$((i + 1))
done

# Touch the first entry again after eviction pressure.
status=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/sec/cache-evict/1/page.html")

rm -rf "$base"

if [ "$failed" -eq 0 ] && [ "$status" = "200" ]; then
    pass
else
    fail "cache eviction failed (first failure at $i, last=$status)"
fi
