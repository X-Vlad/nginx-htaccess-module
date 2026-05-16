# CLAUDE.md

## Project

Native C module for nginx that adds Apache `.htaccess` support. Linux only
(inotify, crypt, lstat). Tested on nginx 1.24.0, 1.28.2, 1.30.1.

## Build

```bash
# Docker (recommended) - override NGINX_VERSION to test other versions
docker build -t nginx-htaccess-test .
docker run --rm nginx-htaccess-test

# Native (requires nginx source)
make build NGINX_VERSION=1.30.1
make test
```

## Test

```bash
docker run --rm nginx-htaccess-test bash /tests/run_tests.sh
cd demo && ./demo.sh                              # interactive demos
```

## Project structure (flat, nginx convention)

- `ngx_http_htaccess_module.{h,c}` - types, module def, phase handlers
- `ngx_http_htaccess_parser.c` - .htaccess tokenizer + directive dispatch
- `ngx_http_htaccess_rewrite.c` - rewrite engine, SetEnvIf, RequestHeader
- `ngx_http_htaccess_access.c` - access control, Basic auth, htgroup, APR1
- `ngx_http_htaccess_header.c` - response header filter, AddType, Expires
- `ngx_http_htaccess_cache.c` - per-worker parsed cache + inotify
- `config` - nginx build integration
- `t/` - shell-based tests (125+ cases)
- `demo/` - Docker demos (simple + WordPress)

## Code style

- nginx conventions: `ngx_` prefixes, `ngx_int_t`/`ngx_str_t`, pool alloc
- Module-internal functions: `hta_` prefix
- No malloc/free - use `ngx_palloc`/`ngx_pnalloc` (request or cycle pool)
- `ngx_str_t` is (pointer, length), not NUL-terminated by default

## Security

- Constant-time compare (`hta_constant_time_memcmp`) on all password hashes
- `hta_secure_zero` (volatile pointer) on passwords and intermediate buffers
- Decoded `Basic` `user:pass` blob zeroed before auth handler returns
- Path-traversal guards on `AuthUserFile`, `AuthGroupFile`, URI traversal,
  REQUEST_FILENAME expansion, all file-test conditions (-f, -d, -l, -e, -s)
- Direct access to `.htaccess`/`.htpasswd`/`.htgroup`/`.htdigest` -> 403
- File-size cap: 1 MB on `.htaccess` / `.htpasswd` / `.htgroup`
- `Require group` inside `<Files>` / `<Limit>` IS propagated (bypass class)
- CR/LF stripped from `Header` and `RequestHeader` values at parse time
- All header lookups use `ngx_strncasecmp` (case-insensitive)

## Common pitfalls

- nginx is single-threaded per worker -> no mutex for per-worker cache
- Dynamic modules require exact nginx version match (ABI compat)
- `ngx_explicit_memzero` is unavailable on older nginx -> use `hta_secure_zero`
- **REWRITE_PHASE handler order is REVERSED by nginx** (`ngx_http_init_phase_handlers`
  walks the array end-to-start). Our REWRITE handler runs BEFORE the rewrite
  module's `set`/`return` script. SetEnv values therefore get re-applied in
  a PREACCESS handler so `set $foo "";` in nginx.conf does not clobber them.
- `.gitignore` uses `.*` with exceptions for `.htaccess`, `.htpasswd`,
  `.github/`, `.gitignore`
- Supported htpasswd hash formats: `$apr1$` (custom impl via ngx_md5),
  `$1$`/`$5$`/`$6$` (glibc crypt), bcrypt `$2[aby]$`, `{SHA}` (ngx_sha1),
  legacy DES. NOT supported: plain-text passwords (rejected by length check).
