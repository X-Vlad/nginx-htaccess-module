# CLAUDE.md

## Project

Native C module for nginx that adds Apache `.htaccess` support. Linux only (inotify, crypt, lstat).

## Build

```bash
# Docker (recommended)
docker build -t nginx-htaccess-test .
docker run --rm nginx-htaccess-test

# Native (requires nginx source)
make build NGINX_VERSION=1.28.2
make test
```

## Test

```bash
# All tests
docker run --rm nginx-htaccess-test bash /tests/run_tests.sh

# Demo
cd demo && ./demo.sh
```

## Project structure

Flat layout (nginx module convention, no src/ directory):

- `ngx_http_htaccess_module.h` - types, constants, declarations
- `ngx_http_htaccess_module.c` - module definition, config, phase handlers
- `ngx_http_htaccess_parser.c` - .htaccess parsing, directive dispatch
- `ngx_http_htaccess_rewrite.c` - rewrite engine, variable expansion, redirects
- `ngx_http_htaccess_access.c` - access control, IP matching, Basic auth
- `ngx_http_htaccess_header.c` - response header filter, AddType, Expires
- `ngx_http_htaccess_cache.c` - per-worker cache with inotify invalidation
- `config` - nginx build system integration
- `t/` - shell-based test suite
- `demo/` - Docker demos (simple + WordPress)

## Code style

- nginx coding conventions: `ngx_` prefixes, `ngx_int_t`/`ngx_str_t` types, pool-based allocation
- Module-internal functions use `hta_` prefix
- No malloc/free - use `ngx_palloc`/`ngx_pnalloc` with request or cycle pools
- Strings are `ngx_str_t` (pointer + length), not null-terminated unless interfacing with libc

## Security considerations

- Constant-time password comparison (`hta_constant_time_strcmp`) to prevent timing attacks
- Secure memory zeroing (`hta_secure_zero` with volatile pointer) after password use
- Path traversal prevention: `..` segments rejected in URI traversal and AuthUserFile paths
- REQUEST_FILENAME expansion checks for `..` before constructing filesystem paths
- File test conditions (-f, -d, -l, -e, -s) reject paths containing `..`
- Direct access to .htaccess/.htpasswd/.htgroup/.htdigest blocked with 403
- File size limits: 1MB max for .htaccess and .htpasswd files
- PCRE match limits controlled by nginx.conf (`pcre_jit on;`), not per-call

## Common pitfalls

- nginx is single-threaded per worker (event-driven), no mutex needed for per-worker cache
- Dynamic modules require exact nginx version match (ABI compatibility)
- `ngx_explicit_memzero` may not exist in older nginx versions, use `hta_secure_zero` instead
- `.gitignore` has `.*` pattern with exceptions for `.htaccess`, `.htpasswd`, `.github/`, `.gitignore`
