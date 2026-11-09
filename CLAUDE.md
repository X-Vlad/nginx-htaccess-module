# CLAUDE.md

## Project

Native C module for nginx that adds Apache `.htaccess` support. Linux only
(inotify, crypt, lstat). Tested on nginx 1.24.0, 1.30.6 (stable), 1.31.8 (mainline).

## Build

```bash
# Docker (recommended) - override NGINX_VERSION to test other versions
docker build -t nginx-htaccess-test .
docker run --rm nginx-htaccess-test

# Native (requires nginx source)
make build NGINX_VERSION=1.30.6
make test
```

## Test

```bash
docker run --rm nginx-htaccess-test bash /tests/t/run_tests.sh
docker run --rm nginx-htaccess-test bash /tests/t/stress.sh   # load/leak test
cd demo && ./demo.sh                                          # interactive demos
```

## Project structure (flat, nginx convention)

- `ngx_http_htaccess_module.{h,c}` - types, module def, phase handlers
- `ngx_http_htaccess_parser.c` - .htaccess tokenizer + directive dispatch
- `ngx_http_htaccess_rewrite.c` - rewrite engine, SetEnvIf, RequestHeader
- `ngx_http_htaccess_access.c` - access control, Basic auth, htgroup, APR1
- `ngx_http_htaccess_header.c` - response header filter, AddType, Expires
- `ngx_http_htaccess_cache.c` - per-worker parsed cache + inotify
- `config` - nginx build integration
- `t/` - shell-based tests (165+ cases)
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
- Direct access to any `.ht*` basename -> 403 (incl. backups like `.htpasswd.bak`)
- File-size cap: 1 MB on `.htaccess` / `.htpasswd` / `.htgroup`
- `Require group` inside `<Files>` / `<Limit>` IS propagated (bypass class)
- Control characters (all but HTAB) stripped from `Header` and
  `RequestHeader` values at parse time; runtime-expanded redirect/header
  values are refused or blanked when they hold one; `RequestHeader` never
  sets `Host`
- Every customer regex goes through `hta_regex_exec`, which charges the
  request's budget (`HTA_REGEX_BUDGET_MS`, `HTA_REGEX_MAX_EXEC`) on top of the
  per-match limits; at most `HTA_MAX_REGEX_PER_FILE` patterns per file. A new
  entry point (phase handler, filter, variable) must wrap its body in
  `hta_regex_enter`/`hta_regex_leave`, and a phase handler never returns
  `NGX_ERROR` (nginx drops the connection silently): return 500
- One per-request budget (`HTA_REGEX_BUDGET_MS` time, `HTA_EXPAND_BUDGET`
  memory) covers every customer-controlled cost: regex matches
  (`hta_regex_exec`), and non-regex work wrapped in
  `hta_work_start`/`hta_work_stop` (condition eval, file tests) or
  `hta_work_alloc` (expansion buffers). New per-request loops over customer
  input must charge one of them, or a cheap directive repeated thousands of
  times is a new DoS
- Expansions use the growing `hta_buf_t` and fail (500) past 1 MB; never
  drop a value that does not fit, a deny rule would then see an empty string
- `php_value` names are `[A-Za-z0-9_.]` only, checked before the dangerous
  list (PHP trims and parses INI syntax, so a name with a space, '=' or ';'
  is another setting in disguise)
- `.htaccess` writes nginx variables (SetEnv*, BrowserMatch, `[E=]`) only
  through `hta_assign_env`, which allows only names in `htaccess_env_allow`
  that are declared with `set`; never write a variable any other way
- All header lookups use `ngx_strncasecmp` (case-insensitive)
- `htaccess_strict` defaults to **on**: parse errors, invalid regexes, unknown
  directives/blocks, unreadable/oversized files and malformed tags fail closed
- `O_NOFOLLOW` + `htaccess_owner_check on` (default) for `.ht*` and auth files;
  `realpath()` confinement for `AuthUserFile`, `AuthGroupFile` and file tests.
  Auth files must match the requesting `.htaccess` owner (cross-tenant block).
  Parse warnings never log file content.
- `root`/`alias` with variables or regex aliases fail closed; unsupported
  `<If>` / `<IfVersion>` blocks fail closed (only `<IfModule>` is evaluated)
- Cache is byte-bounded, paths are inline, inotify watches are removed on
  invalidation, and changes are visible to the next request
- `php_admin_*` is ignored unless `htaccess_allow_php_admin on`; proxy header
  forgery is refused unless `htaccess_allow_proxy_headers on`
- Dangerous `php_value` settings (`auto_prepend_file`, `open_basedir`,
  `session.save_path`, ...) are dropped unless `htaccess_allow_dangerous_php on`
- `Header unset` of security headers is refused unless
  `htaccess_allow_security_unset on`; response framing headers are always
  protected
- `ExpiresActive` is merged root-to-leaf and emitted once, so child `Off`
  removes a parent `Expires` instead of duplicating it
- Request paths escaping the document root via symlinks are denied
  (`htaccess_symlink_check on`); `Options -FollowSymLinks` also rejects
  symlinked components
- AuthType/AuthName/AuthUserFile/AuthGroupFile inherit across `.htaccess`
  files; a child may contain only `Require valid-user`
- ErrorDocument status/precedence: deepest `.htaccess` wins and internal
  error pages keep the original 4xx/5xx status. Static content-phase 404s are
  not intercepted (documented limitation).

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
