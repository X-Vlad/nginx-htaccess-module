# nginx htaccess module (ngx_http_htaccess_module)

Apache-compatible `.htaccess` and `mod_rewrite` support for nginx.

Native C nginx module providing per-directory `.htaccess` processing, rewrite rules, authentication, access control, and shared hosting compatibility.

`ngx_http_htaccess_module` enables nginx to read and apply Apache-compatible `.htaccess` files, including rewrite rules, authentication, access control, and per-directory configuration.

Designed for shared hosting providers migrating from Apache HTTP Server or LiteSpeed to nginx without rewriting customer `.htaccess` files.

[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![nginx](https://img.shields.io/badge/nginx-1.24+-green.svg)](https://nginx.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()
[![Language](https://img.shields.io/badge/language-C-orange.svg)]()

---

## Features

- Apache `.htaccess` support for nginx
- Apache-compatible `mod_rewrite`
- Per-directory rewrite rules
- `.htaccess` rewrite rules
- `.htpasswd` authentication
- Shared hosting `.htaccess` compatibility
- Automatic reload via inotify
- Native C nginx module
- No Lua
- No OpenResty
- Linux only

---

> **Platform:** Linux only. The module uses `inotify` for file change monitoring and `crypt()` from glibc for password hashing. Windows and macOS are not supported.

## Why

Nginx deliberately does not support `.htaccess`. This is the correct architectural decision for pure nginx deployments. However, for **hosting providers** migrating from Apache/LiteSpeed, thousands of customer sites depend on `.htaccess` for URL rewriting, access control, and authentication. Converting each `.htaccess` to nginx config is impractical at scale.

This module solves that problem at the lowest possible overhead: native C, compiled directly into nginx, with aggressive caching and inotify-based invalidation.

## Performance

- Unlike Apache which re-reads `.htaccess` on every request, this module parses once and caches the result per-worker.
- When a `.htaccess` file changes, inotify triggers instant cache invalidation. No polling, no TTL expiration delays. Falls back to mtime-based stat() when inotify is unavailable.
- All parsed data lives in nginx memory pools, no malloc/free churn.

The stress harness in `t/stress.sh` (run on nginx 1.24.0 + 1.30.3) confirms the design holds up under load:

- **Module overhead is effectively zero.** Throughput with `htaccess on` (and a chain of SetEnv / add_header / RequestHeader / rewrite directives) matches the `htaccess off` baseline within measurement noise. The per-worker parsed cache + inotify invalidation absorbs the cost; once a `.htaccess` is in cache, the next request pays only the cost of running the already-parsed rules.
- **Auth cost is the cost of the hash.** Basic-auth throughput is dictated by the htpasswd hash format - `$6$` SHA-512 runs ~5000 crypt rounds, `$apr1$` runs 1000 MD5 rounds. Apache and LiteSpeed pay the same price on the same hashes. For high-rate auth, prefer bcrypt at low cost, or front the auth wall with a session cookie.
- **Memory stays bounded.** Worker RSS grows by a few MB as the parsed-file cache fills, then plateaus. No leaks observed across sustained traffic on three nginx versions.
- **No crashes or critical log entries** across 1.24.0 / 1.28.2 / 1.30.3 under sustained mixed traffic.

Absolute throughput numbers depend heavily on the host environment (kernel, CPU, worker count, network stack), so they're left out here intentionally - run `t/stress.sh` on your own target hardware for representative numbers.

## Supported Directives

### URL Rewriting
| Directive | Status | Notes |
|-----------|--------|-------|
| `RewriteEngine On/Off` | Full | |
| `RewriteBase /path/` | Full | |
| `RewriteCond %{VAR} pattern [flags]` | Full | NC, OR, negation (!); tests -f, -d, -l, -e, -s; string/int compares =, !=, <, >, <=, >=, -eq, -ne, -lt, -le, -gt, -ge; `%1-%9` backrefs; `$N` from the rule pattern (rule matched first, Apache order) |
| `RewriteRule pattern substitution [flags]` | Full | Short + long flag names (L/last, R=CODE/redirect=, F/forbidden, G/gone, NC/nocase, NE/noescape, QSA/qsappend, QSD/qsdiscard, PT/passthrough, C/chain, S=N/skip, E=key:val/env). `R=` allows 4xx/5xx (e.g. `- [R=404]`). `E=` value is variable-expanded |
| `Redirect [status] source target` | Full | 301, 302, 303, 410, permanent, temp, seeother, gone; original `?query` is carried through |
| `RedirectMatch [status] pattern target` | Full | Regex with backreferences; `?query` carried through |
| `RedirectPermanent source target` | Full | Shortcut for 301 |
| `RedirectTemp source target` | Full | Shortcut for 302 |

### Directory & File Handling
| Directive | Status | Notes |
|-----------|--------|-------|
| `DirectoryIndex file1 file2 ...` | Full | Multiple index files with filesystem check |
| `FallbackResource /index.php` | Full | Front controller when the request maps to no existing file (`disabled` clears it) |
| `ErrorDocument code response` | Partial | URL path / external URL, deepest `.htaccess` wins, internal page keeps the original status; text-message form returns the status only. Fires on module/access-phase errors; a static 404 produced by the content phase is not intercepted |
| `Options -Indexes ...` | Partial | `-Indexes` and `-FollowSymLinks` enforced; `MultiViews`/`All`/`None` parsed. Symlinks resolving outside the document root are always denied |
| `ForceType mime/type` | Full | Also within `<Files>` blocks |
| `DefaultType mime/type` | Full | Fallback content type |
| `AddType mime/type .ext1 .ext2` | Full | Multiple extensions per directive |
| `AddDefaultCharset charset` | Full | Appends charset to text/* Content-Type |

### Access Control
| Directive | Status | Notes |
|-----------|--------|-------|
| `Order Deny,Allow / Allow,Deny` | Full | Apache 2.2 style |
| `Allow from` / `Deny from` | Full | all, IP, prefix, CIDR notation (IPv4 + IPv6) |
| `Require all granted/denied` | Full | Apache 2.4 style |
| `Require ip` / `Require host` | Full | |
| `Require valid-user` / `Require user` | Full | |
| `Require group <name>` | Full | Resolved against `AuthGroupFile` |
| `Satisfy Any` / `Satisfy All` | Full | Either or both of access+auth (default All) |

### Authentication
| Directive | Status | Notes |
|-----------|--------|-------|
| `AuthType Basic` | Full | |
| `AuthName "realm"` | Full | |
| `AuthUserFile /path/.htpasswd` | Full | Multiple hash formats (see below) |
| `AuthGroupFile /path/.htgroup` | Full | Apache htgroup format: `group: user1 user2` |

Supported `.htpasswd` hash formats:

| Hash prefix | Format | Source |
|-------------|--------|--------|
| `$apr1$...` | Apache MD5 (APR1)            | `htpasswd -m` (default Apache) |
| `$2a$` / `$2b$` / `$2y$` | bcrypt        | `htpasswd -B` / `openssl passwd -2y` |
| `$5$` | crypt SHA-256                       | `openssl passwd -5` |
| `$6$` | crypt SHA-512                       | `openssl passwd -6` |
| `$1$` | crypt MD5                            | `openssl passwd -1` |
| `{SHA}<b64>` | base64(SHA-1(password))      | `htpasswd -s` |
| 13 bytes, no prefix | legacy DES crypt      | classic `crypt(3)` |

### Response Headers
| Directive | Status | Notes |
|-----------|--------|-------|
| `Header [always] set name value` | Full | Replaces existing header |
| `Header [always] unset name` | Full | |
| `Header [always] append name value` | Full | |
| `Header [always] add name value` | Full | |
| `Header [always] merge name value` | Full | Deduplicates values |

`Header` accepts a trailing `env=VAR` / `env=!VAR` condition (applied only when the nginx variable is set / unset), e.g. SetEnvIf-gated CORS.

### Request Headers (forwarded to upstream)
| Directive | Status | Notes |
|-----------|--------|-------|
| `RequestHeader set name value` | Full | Replaces incoming header on `r->headers_in` |
| `RequestHeader unset name` | Full | Removes all copies of the header |
| `RequestHeader add name value` | Full | Appends a duplicate (multi-value) |
| `RequestHeader append name value` | Full | Same as add |
| `RequestHeader merge name value` | Full | Add unless value already present |
| `RequestHeader edit / edit*` | Skipped | Logged as warning; regex-replace not implemented |

`RequestHeader` values expand `%{VAR}e` / `%{VAR}s` / `%{VAR}` from nginx variables (e.g. Nextcloud's `RequestHeader set Authorization %{HTTP_AUTHORIZATION}e`).

### Caching
| Directive | Status | Notes |
|-----------|--------|-------|
| `ExpiresActive On/Off` | Full | |
| `ExpiresDefault "access plus N days"` | Full | Parses duration strings (years, months, weeks, days, hours, minutes, seconds) |
| `ExpiresByType mime/type "..."` | Full | Per-MIME-type expiration |

### Environment
| Directive | Status | Notes |
|-----------|--------|-------|
| `SetEnv name [value]` | Full | Unconditional; sets nginx variable |
| `UnsetEnv name` | Full | Marks variable as not-found |
| `SetEnvIf attribute pattern env[=val]...` | Full | Multiple env= tokens, `!env` to unset; `$1-$9` regex backrefs allowed in the value |
| `SetEnvIfNoCase attribute pattern env[=val]...` | Full | Case-insensitive regex |
| `BrowserMatch pattern env[=val]...` | Full | Shorthand for `SetEnvIf User-Agent ...` |
| `BrowserMatchNoCase pattern env[=val]...` | Full | Case-insensitive variant |

The variable target must be declared somewhere nginx knows about
(`set $foo "";` in nginx.conf, or a `map` at http level) — that's an nginx
constraint, not Apache. The values become visible to upstream via
`fastcgi_param X $foo;` / `proxy_set_header X $foo;`.

### SSL / TLS
| Directive | Status | Notes |
|-----------|--------|-------|
| `SSLRequireSSL` | Full | Returns 403 for plain HTTP; honors `X-Forwarded-Proto: https` only when `htaccess_trust_proxy on` (secure default: header ignored) |
| `SSLRequire` | Partial | Treated as `SSLRequireSSL` (Apache expression syntax is not parsed) |

### PHP Settings (forwarded to PHP-FPM)
| Directive | Status | Notes |
|-----------|--------|-------|
| `php_value name value` | Full | Collected into `$htaccess_php_value`; dangerous settings are filtered (see Security) |
| `php_admin_value name value` | Full | Collected into `$htaccess_php_admin_value` |
| `php_flag name on/off` | Full | Collected into `$htaccess_php_value`; `php_flag engine off` also blocks script execution |
| `php_admin_flag name on/off` | Full | Collected into `$htaccess_php_admin_value` |

Wire the two nginx variables into your PHP location to apply the collected ini settings per-request:

```nginx
location ~ \.php$ {
    fastcgi_pass   unix:/run/php/php-fpm.sock;
    fastcgi_param  PHP_VALUE        $htaccess_php_value;
    fastcgi_param  PHP_ADMIN_VALUE  $htaccess_php_admin_value;
    include        fastcgi_params;
}
```

The variables are empty strings when no `php_*` directives are in scope, which is a no-op for PHP-FPM.

### Block Directives
| Directive | Status | Notes |
|-----------|--------|-------|
| `<IfModule mod_xxx>` | Full | Treated as always-present; negation (!) supported |
| `<Files "pattern">` | Full | Exact match, prefix/suffix wildcards |
| `<FilesMatch "regex">` | Full | PCRE regex against basename |
| `<Limit METHOD ...>` | Full | Contained directives apply only to listed methods |
| `<LimitExcept METHOD ...>` | Full | Contained directives apply to all methods except listed |
| `<RequireNone>` | Full | Inner `Require ip/host/env` invert to Deny (ban list) |
| `<RequireAll>` / `<RequireAny>` | Partial | Inner requirements are flattened; the common `valid-user` + `ip` mix works via `Satisfy`, but multi-host AND/OR grouping is not distinguished |
| `<Directory>` / `<Location>` | Fail closed | Not valid in `.htaccess`; the file is rejected |
| `<If>` / `<ElseIf>` / `<Else>` | Fail closed | Apache expressions are not evaluated; file is rejected |

`<Limit>` recognizes GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH, TRACE, PROPFIND, PROPPATCH, COPY, MOVE, MKCOL, LOCK, UNLOCK. Nesting `<Limit>` inside `<Files>` or `<Files>` inside `<Limit>` is rejected (fails closed).

### Script-execution kill-switch
`SetHandler none` / `SetHandler default-handler`, `RemoveHandler .php`, and
`php_flag engine off` block script execution for the matching files (return
403), so upload-directory hardening works. This only fires when the module is
enabled in the location that serves the scripts (e.g. `location ~ \.php$`),
since that is where the request lands.

### Gracefully Ignored
These directives are recognized but silently ignored (correct behavior for nginx+FPM, or features that don't map to nginx):
- `AddHandler` (use the FPM location for PHP mapping)
- `AddCharset`
- `AddEncoding`, `AddLanguage`, `LanguagePriority`, `ForceLanguagePriority`
- `AddInputFilter`, `AddOutputFilter`, `AddOutputFilterByType`
- `SetInputFilter`, `SetOutputFilter`
- `RemoveType`
- `ServerSignature`, `FileETag`, `LimitRequestBody`
- `SSLOptions`
- `Action`, `PassEnv`
- `SecFilterEngine`, `SecFilterScanPOST` (mod_security)
- `RewriteMap` (logged as warning, not supported)

### Server Variables
Apache server variables in `RewriteCond`, `RewriteRule` substitutions, and `SetEnvIf`:

```
REQUEST_URI, REQUEST_FILENAME, SCRIPT_FILENAME, QUERY_STRING, HTTP_HOST,
HTTP_USER_AGENT, HTTP_REFERER, HTTP_COOKIE, HTTP_ACCEPT,
HTTP_ACCEPT_LANGUAGE, REMOTE_ADDR, REMOTE_HOST, REQUEST_METHOD,
SERVER_NAME, SERVER_PORT, SERVER_PROTOCOL, HTTPS, THE_REQUEST,
DOCUMENT_ROOT, REQUEST_SCHEME,
TIME, TIME_YEAR, TIME_MON, TIME_DAY, TIME_HOUR, TIME_MIN, TIME_SEC, TIME_WDAY
```

Also `%{HTTP:Header-Name}` (arbitrary request header) and `%{ENV:name}` (an env
var populated by SetEnv/SetEnvIf/`[E=]`). `REQUEST_FILENAME`/`SCRIPT_FILENAME`
resolve correctly under `alias` locations. Any other name falls back to an
nginx variable lookup.

## Security

- Direct access to any `.ht*` basename is blocked with 403 (covers backups/editor swap files like `.htpasswd.bak`, `.htaccess~`), not just the four canonical names.
- Standalone `Require ip`/`Require host` denies non-matching clients (Apache 2.4 authz), rather than degrading to allow-all under the default `Order deny,allow`.
- `AuthType`/`AuthName`/`AuthUserFile`/`AuthGroupFile` are inherited from parent `.htaccess` files, so a child may contain only `Require valid-user`. A password/group file must be owned by the same tenant as the `.htaccess` (otherwise 500), on top of the path confinement.
- `AuthType Digest` or any unsupported AuthType fails closed (500), and a `Require` with no usable AuthType never silently grants access. Per-file `Require` in `<Files>`/`<Limit>` inherits the enclosing AuthType.
- `<Limit GET>` also constrains HEAD; `SSLRequireSSL` trusts `X-Forwarded-Proto` only with `htaccess_trust_proxy on`.
- File paths are validated within document root boundaries (path traversal prevention) on `AuthUserFile`, `AuthGroupFile`, and all file-test conditions.
- `.htaccess`, `.htpasswd`, and `.htgroup` files larger than 1MB are rejected.
- `Require valid-user` without `AuthUserFile` returns 500 instead of silently accepting.
- `Require group <name>` without `AuthGroupFile` returns 500.
- `Require group` inside `<Files>` / `<Limit>` blocks IS enforced (the group fields are propagated into the per-block auth check; not enforcing them would be an auth bypass).
- Password verification uses constant-time comparison for all supported hash formats (DES, MD5, SHA-1/256/512, bcrypt, APR1) to defeat timing attacks.
- Decoded Basic-auth `user:pass` plaintext is zeroed before the auth handler returns; intermediate buffers in the APR1 implementation are zeroed too.
- Basic-auth password length is capped at 1024 bytes before reaching the verifier (defensive bound for the APR1 bit-shift loop).
- `Header` / `RequestHeader` values have CR/LF stripped at parse time to prevent response or upstream-request splitting.
- `php_value` / `php_admin_value` values have CR / LF / `"` / NUL replaced with spaces before being concatenated into the `PHP_VALUE` fastcgi param.
- All response/request-header lookups are case-insensitive (`ngx_strncasecmp`), so client variations like `x-forwarded-proto` match the same as `X-Forwarded-Proto`.
- `htaccess_strict` now defaults to **on**: an unknown directive, invalid regex, unreadable/oversized `.htaccess`, malformed `<Files>` tag, or unsupported block fails closed (500) instead of silently dropping protection.
- Security-sensitive files are opened with `O_NOFOLLOW`; `htaccess_owner_check on` (default) additionally requires the file owner to match the containing directory. Symlinked or foreign-owned `.htaccess`, `.htpasswd`, `.htgroup`, and `AuthUserFile`/`AuthGroupFile` targets are rejected. Parse warnings no longer include file content.
- `AuthUserFile`, `AuthGroupFile`, and `RewriteCond -f/-d/-l/-e/-s` paths are confined to the document root with `realpath()`; outside paths behave as missing. Auth files are additionally required to belong to the same Unix owner as the requesting `.htaccess`, blocking cross-tenant password-file use.
- Request paths whose `realpath()` escapes the document root through a symlink are denied (`htaccess_symlink_check on`, default). `Options -FollowSymLinks` additionally rejects any symlink component below the root.
- All access/auth/.ht* checks also run for subrequests (SSI includes, `auth_request`), not only the main request.
- `root`/`alias` values containing nginx variables or regex aliases fail closed (500); they are not silently treated as "no `.htaccess`".
- Dynamic redirect/header values containing CR, LF, or NUL are rejected; response framing headers (`Content-Length`, `Transfer-Encoding`, `Connection`, ...) cannot be set/removed from `.htaccess`; request proxy headers (`X-Forwarded-*`, `Forwarded`, `X-Real-IP`, ...) can only be forged with `htaccess_allow_proxy_headers on`.
- Cache memory is bounded (`HTA_CACHE_MAX_BYTES`/`HTA_PASSWD_MAX_BYTES`), paths are stored inline (no unbounded `path_pool`), inotify watches are removed on invalidation/eviction, and changes are detected on the next request (no 64-request window).
- Compiled customer regexes have pattern-size, compiled-size, match-limit and depth-limit budgets. Tokenization is single-pass and linear.
- `php_admin_value`/`php_admin_flag` from `.htaccess` are ignored by default; set `htaccess_allow_php_admin on` only for single-tenant / trusted setups. `php_value` settings that can escape the site or leak across tenants (`auto_prepend_file`, `auto_append_file`, `open_basedir`, `disable_functions`, `extension`, `include_path`, `error_log`, `session.save_path`, `upload_tmp_dir`, `allow_url_include`, ...) are dropped unless `htaccess_allow_dangerous_php on`. PHP-FPM pools that consume `PHP_VALUE` should still be dedicated per customer because PHP settings can persist in a worker.
- `Header unset` cannot remove common security headers (`Strict-Transport-Security`, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, CORP/COOP/COEP, ...) set by a parent scope unless `htaccess_allow_security_unset on`; response framing headers (`Content-Length`, `Transfer-Encoding`, `Connection`, ...) can never be set or removed.
- `ExpiresActive` state is merged root-to-leaf and the header is emitted once, so `ExpiresActive Off` in a child removes a parent-generated `Expires`/`Cache-Control` instead of leaving a stale value or duplicate.
- `<Limit>` inside `<Files>`, nested `<Limit>/<Files>`, `<If>`/`<IfVersion>` and unknown blocks now fail closed rather than being silently skipped. (`<IfModule>` and `<IfModule !mod>` are still supported.)
- Path/depth/candidate/header/auth-list caps fail closed (500) instead of silently dropping the overflowing security directives.
- Customer regexes have a CPU budget per request: at most 50 ms of total match time and 4096 matches across every `RewriteRule`, `RewriteCond`, `<FilesMatch>`, `SetEnvIf`, `BrowserMatch` and `RedirectMatch` (plus a per-match limit of 100000 steps, depth 250), and at most 1024 patterns per file. Over a budget the request fails closed with 500 and one error line; before, 8192 patterns just under the per-match limit could keep a worker, and every site it serves, busy for minutes per request.
- A regex or internal error in a phase handler answers 500 instead of dropping the connection without a log line.
- `SetEnv`/`SetEnvIf`/`UnsetEnv`/`BrowserMatch` and the `[E=]` rewrite flag write only variables listed in `htaccess_env_allow` (default: none) that are declared with `set`. Before, `[E=]` could overwrite any variable, including `$remote_addr` (forged access logs, so fail2ban could be made to ban any address, and a forged `REMOTE_ADDR` for PHP), and `SetEnv` could rewrite an operator's own `set $var`, such as a `limit_conn` key (one customer could move their requests into another customer's connection limit, or out of every limit).
- No control character but HTAB reaches a response or request header: static `Header`/`RequestHeader` values drop them at parse time, values built at run time (redirect targets, expanded headers) are refused or blanked (before, only CR, LF and NUL were).
- `RequestHeader` cannot set `Host` (it added a second `Host` line, which upstreams reject).
- `<Files "">` (an empty pattern, which matches nothing) fails closed instead of silently not applying its rules.
- A missing, oversized, foreign-owned or out-of-root `AuthUserFile`/`AuthGroupFile` is logged with its path (it already failed closed).
- Expanded values (`%{QUERY_STRING}`, `%{HTTP_USER_AGENT}`, `$N`, `%N`, ...) are never dropped for length: they grow up to 1 MB and beyond that the request fails closed. Before, any value over 4 KB vanished from the condition, so "deny if the query string contains union select" was skipped by adding a long parameter.
- `php_value`/`php_flag` setting names must be `[A-Za-z0-9_.]`; names such as `"auto_prepend_file "` or `"auto_prepend_file=/x;"` slipped past the dangerous-settings list and still reached PHP as that setting. Control characters in values become spaces. `mail.force_extra_parameters`, `sendmail_path`, `user_ini.filename`, `opcache.file_cache` and `opcache.restrict_api` joined the dangerous list.
- An inotify event invalidates every cache entry of its watch (one `.htaccess` reached through a directory symlink inside the root had a stale second entry), and permission/link changes (`IN_ATTRIB`) invalidate too.
- `Options -Indexes` reads nginx's own `index` list on 1.31.x as well (it fell back to the default names).
- Copies of paths kept for later in the request (an inherited `AuthUserFile`/`AuthGroupFile`) are NUL-terminated; they were read past their end as C strings.
- Without inotify (NFS, watch limits) a changed `.htaccess` is recognised by mtime and ctime with nanoseconds, inode, device and size; mtime in whole seconds missed a second edit within the same second, so a just-added deny rule could stay unapplied.
- The per-request budget covers all customer work, not only regex matches: condition evaluation, `RewriteCond` file tests and `%{VAR}`/`$N` expansions share one time budget (50 ms) and expansions share a 4 MB memory budget. Without it, 8160 `-f` conditions across 16 nested directories cost about 2 s of a worker per request, and 8160 conditions each expanding `%{QUERY_STRING}` seven times grew a worker by ~760 MB; both now end at the budget with 500.
- `t/24-tenant-limits.t.sh` covers all of the above; a mutation fuzzer ran 19000 `.htaccess` variants against ASan builds of 1.30.6 and 1.31.8 without a crash.

### Overhead

Measured on a real WordPress 6 site (51 posts, Yoast SEO, PHP 8.5-FPM) with a 38-line `.htaccess` (the WordPress block, `<FilesMatch>` denies, security headers, `Expires`), module on vs off, same nginx and backend:

| Request | Module off | Module on | Added |
|---------|-----------|-----------|-------|
| static file, warm cache (per request) | 0.064 ms | 0.086 ms | ~0.022 ms |
| dynamic WP page (index.php) | ~55 ms | ~55 ms | within noise |
| static file, each of 8 nested directories has its own `.htaccess` | - | +~0.007 ms per level | - |
| static file, 128-condition `.htaccess` | - | 0.091 ms | - |

Worker RSS was unchanged (about 11 MB) and flat over 100000 requests (no per-request leak). The parsed-`.htaccess` cache is per worker and bounded by `HTA_CACHE_MAX_BYTES` (64 MB); it holds the compiled rules and PCRE2 programs, evicting least-recently-used entries past the budget. The per-request cost is the directory walk that stats one `.htaccess` per level plus the cached rules; parsing happens once per file and is then cached.
- Operators: `%{ENV:name}`, `%{name}` and `SetEnvIf` read nginx variables by name, so do not keep secrets in nginx variables of locations where `.htaccess` is on.
- Cross-tenant regression coverage: `t/23-hardening.t.sh` creates two Unix owners and verifies symlinked directory escapes, hardlinked/symlinked `.htaccess`, and an `AuthUserFile` pointing at the other tenant are all rejected.

## Installation

### Quick Install (recommended)

```bash
git clone https://github.com/X-Vlad/nginx-htaccess-module.git
cd nginx-htaccess-module
sudo ./install.sh
```

The installer will:
- Detect your nginx version (or offer to install nginx)
- Download matching nginx source
- Build the dynamic module
- Install `.so` to the modules directory
- Add `load_module` to `nginx.conf`

```bash
./install.sh --check       # check installation status
sudo ./install.sh --uninstall   # remove module
```

### Manual Build (dynamic module)

```bash
# Download nginx source matching your installed version
nginx -v  # note the version
wget https://nginx.org/download/nginx-X.Y.Z.tar.gz
tar xzf nginx-X.Y.Z.tar.gz
cd nginx-X.Y.Z

# Configure and build
./configure --with-compat --add-dynamic-module=/path/to/nginx-htaccess-module
make modules

# Install
sudo cp objs/ngx_http_htaccess_module.so /usr/lib/nginx/modules/
```

### Build as Static Module

```bash
./configure --add-module=/path/to/nginx-htaccess-module
make && sudo make install
```

### Requirements

- **Linux** (kernel 2.6.13+ for inotify)
- **PCRE** (libpcre or libpcre2) for regex support
- **glibc with crypt()** for htpasswd authentication (`-lcrypt`)

On Debian/Ubuntu:
```bash
apt-get install build-essential libpcre3-dev zlib1g-dev libssl-dev
```

On RHEL/CentOS/AlmaLinux:
```bash
yum install gcc make pcre-devel zlib-devel openssl-devel
```

### Tested nginx versions

The test suite is run against these nginx releases, each also under ASan/UBSan where marked:

| Version | Status |
|---------|--------|
| 1.24.0 (oldest supported) | All tests pass |
| 1.26.3 (Debian 13 package version) | All tests pass, on Ubuntu 26.04 and Debian 13 |
| 1.28.3 (Ubuntu 26.04 package version) | All tests pass |
| 1.30.6 (stable, default in Dockerfile) | All tests pass, also under ASan/UBSan, on Ubuntu 26.04 and Debian 13 |
| 1.31.8 (mainline) | All tests pass, also under ASan/UBSan |

Also run: the whole suite with `openat2` refused (kernels before 5.6), with `inotify` refused (NFS, watch limits) and with `pcre_jit on`; a 5-minute soak with 8 workers, mixed traffic, 782 `.htaccess` edits (every edit checked on all workers at once) and 10 reloads; HTTP/2 (`h2load`, 600000 multiplexed requests) and HTTP/3; and a real WordPress site, whose 43 test requests (pages, REST API, login and dashboard, sitemaps, feeds, denied files, caching, bot blocking) answer exactly as the equivalent hand-written nginx configuration.

Override the version at build time:
```bash
docker build --build-arg NGINX_VERSION=1.31.8 \
  --build-arg NGINX_SHA256=0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1 \
  -t nginx-htaccess-test:1.31.8 .
```

## Configuration

### Minimal

```nginx
load_module modules/ngx_http_htaccess_module.so;

http {
    server {
        listen 80;
        root /var/www/html;

        location / {
            htaccess on;
        }
    }
}
```

### Full

```nginx
load_module modules/ngx_http_htaccess_module.so;

http {
    server {
        listen 80;
        server_name example.com;
        root /var/www/example.com;

        location / {
            htaccess on;
            htaccess_filename .htaccess;  # default, can be changed
        }

        # Disable htaccess for specific locations
        location /api/ {
            htaccess off;
        }
    }
}
```

### Directives

| Directive | Context | Default | Description |
|-----------|---------|---------|-------------|
| `htaccess` | http, server, location | `off` | Enable/disable .htaccess processing |
| `htaccess_filename` | http, server, location | `.htaccess` | Name of the htaccess file to look for |
| `htaccess_strict` | http, server, location | `on` | Fail closed (500) when a `.htaccess` uses an unrecognized directive, has a parse error, or hits a parser/candidate limit |
| `htaccess_owner_check` | http, server, location | `on` | Require `.ht*` and auth files to be owned by the containing directory / requesting tenant |
| `htaccess_symlink_check` | http, server, location | `on` | Deny request paths whose realpath escapes the document root through a symlink |
| `htaccess_allow_php_admin` | http, server, location | `off` | Allow `php_admin_*` from `.htaccess` (trusted single-tenant only) |
| `htaccess_allow_dangerous_php` | http, server, location | `off` | Allow `auto_prepend_file`, `open_basedir`, etc. from `php_value` |
| `htaccess_allow_proxy_headers` | http, server, location | `off` | Allow `RequestHeader` to forge `X-Forwarded-*`/`Forwarded`/`X-Real-IP` |
| `htaccess_allow_security_unset` | http, server, location | `off` | Allow `Header unset` of security headers set by a parent scope |
| `htaccess_trust_proxy` | http, server, location | `off` | Trust `X-Forwarded-Proto` for `SSLRequireSSL` (enable only when nginx sits behind a TLS-terminating proxy that overwrites the header) |
| `htaccess_env_allow` | http, server, location | none | Variables `SetEnv`, `SetEnvIf`, `UnsetEnv`, `BrowserMatch` and `[E=]` may write: names, or prefixes ending in `*`; `*` alone allows every variable declared with `set` (single-tenant only). The variable must also be declared with `set` |

## Architecture

```
Request → nginx
           │
           ├─ REWRITE phase
           │   ├─ Collect .htaccess files (root → deepest dir)
           │   ├─ Parse & cache each file (inotify invalidation)
           │   ├─ Apply SetEnvIf (early, for RewriteCond %{ENV:FOO})
           │   ├─ Apply RequestHeader (modify r->headers_in)
           │   ├─ Apply DirectoryIndex
           │   ├─ Apply Redirect/RedirectMatch
           │   └─ Apply RewriteRules with RewriteConds
           │       ├─ Variable expansion (%{VAR})
           │       ├─ Backreference substitution ($1..$9)
           │       ├─ [E=var:val] environment variable setting
           │       └─ Chain/Skip/QSA/QSD/Redirect handling
           │
           ├─ PREACCESS phase
           │   └─ Re-apply SetEnv / SetEnvIf so the final values survive
           │     any `set $foo "";` in the location's rewrite script
           │     (nginx reverses REWRITE_PHASE handler order, so our
           │      REWRITE handler actually runs BEFORE the `set` script)
           │
           ├─ ACCESS phase
           │   ├─ Block .htaccess/.htpasswd/.htgroup/.htdigest (403)
           │   ├─ Enforce SSLRequireSSL
           │   ├─ Combine access + auth via Satisfy Any/All
           │   ├─ Apply Order/Allow/Deny + Require (incl. group)
           │   ├─ Apply Basic Authentication (htpasswd + htgroup)
           │   ├─ Apply <Files>/<FilesMatch> access + auth
           │   ├─ Apply <Limit>/<LimitExcept> access + auth
           │   └─ ErrorDocument redirect on errors
           │
           └─ HEADER FILTER phase
               ├─ Apply Header set/unset/append/add/merge
               ├─ Apply ForceType / DefaultType / AddType
               ├─ Apply AddDefaultCharset
               ├─ Apply <Files>/<FilesMatch> block headers
               └─ Apply Expires headers (Cache-Control + Expires)
```

### Directory Traversal

For a request to `/site/blog/post.php` with document root `/var/www`, the module checks:

```
/var/www/.htaccess              ← root level
/var/www/site/.htaccess         ← subdirectory
/var/www/site/blog/.htaccess    ← deepest directory
```

All found files are parsed and applied in order (root → deepest), matching Apache behavior.

### Caching

Each nginx worker maintains its own cache (no locking needed). Cache entries are keyed by file path and invalidated via:

1. **inotify** (instant) - watches for IN_MODIFY, IN_DELETE_SELF, IN_MOVE_SELF
2. **stat()** (fallback) - checks mtime when inotify is unavailable

Cache capacity: 1024 entries per worker with FIFO eviction.

## File Structure

```
ngx_http_htaccess_module.h      Types, constants, cross-file declarations
ngx_http_htaccess_module.c      Module definition, config, phase handlers
ngx_http_htaccess_parser.c      .htaccess file parsing, directive dispatch
ngx_http_htaccess_rewrite.c     Rewrite engine, variable expansion, redirects
ngx_http_htaccess_access.c      Access control, IP matching, Basic auth
ngx_http_htaccess_header.c      Response header filter, AddType, Expires
ngx_http_htaccess_cache.c       Per-worker cache with inotify invalidation
config                          nginx build system integration
```

## Testing

### Test Suite

125 automated tests covering all major features:

```bash
# Build and run tests in Docker
docker build -t nginx-htaccess-test .
docker run --rm nginx-htaccess-test
```

### Stress test

A separate stress harness in `t/stress.sh` hammers each path with `ab` and reports throughput, memory growth, and worker liveness. Run it on the same image:

```bash
docker run --rm \
    -v "$(pwd)/t/stress.sh:/tests/t/stress.sh" \
    nginx-htaccess-test \
    bash /tests/t/stress.sh
```

The harness fails the run if any scenario sees a non-zero error count, the worker process dies, the worker RSS grows by more than 8 MB, or the error log has any `[alert]` / `[crit]` / `[emerg]` entries.

| Category | Tests | Coverage |
|----------|------:|----------|
| RewriteRule + RewriteCond | 15 | All flags, backreferences, NC, R=301/302, F, G, QSA, QSD, chain, env, HTTP_HOST / REQUEST_URI / negation / -f |
| Redirect | 6 | 301, 302, permanent, temp, gone (410), RedirectMatch |
| Access Control | 4 | Require all, Order Deny/Allow |
| Authentication | 5 | Basic auth, correct/wrong credentials, WWW-Authenticate |
| Headers | 4 | Header set, AddDefaultCharset, AddType |
| Expires | 4 | ExpiresActive, ExpiresDefault, ExpiresByType |
| DirectoryIndex | 2 | Index file serving |
| ErrorDocument | 2 | Custom 404, normal file passthrough |
| Files blocks | 3 | Files deny, Files allow, FilesMatch headers |
| SetEnvIf (legacy) | 2 | Attribute matching, User-Agent |
| Limit / LimitExcept | 7 | POST/PUT auth, GET-only allowlist, method-targeted deny |
| Security | 5 | .htaccess/.htpasswd/.htdigest blocking |
| SSLRequireSSL | 3 | Plain HTTP denied, X-Forwarded-Proto honored |
| php_value | 8 | Collection, admin/non-admin separation, empty-when-absent |
| SetEnv / BrowserMatch | 7 | Unconditional, regex, case-insensitive variants |
| Satisfy | 4 | Any (IP or auth), default All (IP and auth) |
| Hash formats | 5 | `{SHA}` and `$apr1$` accept and reject |
| AuthGroupFile | 5 | `Require group` + `<Files>` enforcement (auth-bypass regression) |
| RequestHeader | 6 | set/unset/add, case-insensitive client header matching |
| CMS Compatibility | 28 | Parse + runtime tests for 10 CMS/frameworks |
| **Total** | **125** | |

### CMS Compatibility

Tested with real `.htaccess` files from:
- WordPress (core + security plugins: Wordfence, iThemes Security)
- Laravel (root and public/.htaccess)
- CodeIgniter (clean URLs)
- Joomla (extensive RewriteRules)
- Drupal (clean URLs, security FilesMatch blocks)
- Magento 1.x / 2.x (multi-level rewrites, SetEnvIf, Expires)
- OpenCart (QSA rewrites)
- PrestaShop (complex rewrites)
- DLE / DataLife Engine (multiple rewrite rules)
- MODX (clean URLs)

**Not applicable to nginx (correctly ignored):** `AddHandler`/`SetHandler` (use FPM), `mod_deflate` (use `gzip on` in nginx.conf), `mod_security` (use `ngx_http_modsecurity_module`).

## Demo

The `demo/` directory contains Docker-based demos:

```bash
cd demo
./demo.sh         # Linux/macOS, interactive menu
demo.bat          # Windows, interactive menu (requires Docker Desktop)
```

**Simple Demo** (nginx + PHP-FPM 8.4):
```bash
docker compose up -d          # http://localhost:8080
```

**WordPress Demo** (nginx + PHP-FPM 8.4 + MySQL 8.0):
```bash
docker compose -f docker-compose.wordpress.yml up -d   # http://localhost:8080
# MySQL: host=mysql db=wordpress user=wp pass=wppass
```

## License

BSD-2-Clause
