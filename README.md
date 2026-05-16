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

The stress harness in `t/stress.sh` (run on nginx 1.24.0 + 1.30.1) confirms the design holds up under load:

- **Module overhead is effectively zero.** Throughput with `htaccess on` (and a chain of SetEnv / add_header / RequestHeader / rewrite directives) matches the `htaccess off` baseline within measurement noise. The per-worker parsed cache + inotify invalidation absorbs the cost; once a `.htaccess` is in cache, the next request pays only the cost of running the already-parsed rules.
- **Auth cost is the cost of the hash.** Basic-auth throughput is dictated by the htpasswd hash format - `$6$` SHA-512 runs ~5000 crypt rounds, `$apr1$` runs 1000 MD5 rounds. Apache and LiteSpeed pay the same price on the same hashes. For high-rate auth, prefer bcrypt at low cost, or front the auth wall with a session cookie.
- **Memory stays bounded.** Worker RSS grows by a few MB as the parsed-file cache fills, then plateaus. No leaks observed across sustained traffic on three nginx versions.
- **No crashes or critical log entries** across 1.24.0 / 1.28.2 / 1.30.1 under sustained mixed traffic.

Absolute throughput numbers depend heavily on the host environment (kernel, CPU, worker count, network stack), so they're left out here intentionally - run `t/stress.sh` on your own target hardware for representative numbers.

## Supported Directives

### URL Rewriting
| Directive | Status | Notes |
|-----------|--------|-------|
| `RewriteEngine On/Off` | Full | |
| `RewriteBase /path/` | Full | |
| `RewriteCond %{VAR} pattern [flags]` | Full | NC, OR, negation (!), -f, -d, -l, -e, -s |
| `RewriteRule pattern substitution [flags]` | Full | L, END, R, R=301, F, G, NC, NE, QSA, QSD, PT, C, S=N, E=key:val |
| `Redirect [status] source target` | Full | 301, 302, 303, 410, permanent, temp, seeother, gone |
| `RedirectMatch [status] pattern target` | Full | Regex with backreferences |
| `RedirectPermanent source target` | Full | Shortcut for 301 |
| `RedirectTemp source target` | Full | Shortcut for 302 |

### Directory & File Handling
| Directive | Status | Notes |
|-----------|--------|-------|
| `DirectoryIndex file1 file2 ...` | Full | Multiple index files with filesystem check |
| `ErrorDocument code response` | Full | URL path, external URL, or text response |
| `Options +-Indexes +-FollowSymLinks +-MultiViews` | Full | All/None keywords, SymLinksIfOwnerMatch |
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

### Request Headers (forwarded to upstream)
| Directive | Status | Notes |
|-----------|--------|-------|
| `RequestHeader set name value` | Full | Replaces incoming header on `r->headers_in` |
| `RequestHeader unset name` | Full | Removes all copies of the header |
| `RequestHeader add name value` | Full | Appends a duplicate (multi-value) |
| `RequestHeader append name value` | Full | Same as add |
| `RequestHeader merge name value` | Full | Add unless value already present |
| `RequestHeader edit / edit*` | Skipped | Logged as warning; regex-replace not implemented |

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
| `SetEnvIf attribute pattern env[=val]...` | Full | Multiple env= tokens, `!env` to unset on match |
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
| `SSLRequireSSL` | Full | Returns 403 for plain HTTP; honors `X-Forwarded-Proto: https` |
| `SSLRequire` | Partial | Treated as `SSLRequireSSL` (Apache expression syntax is not parsed) |

### PHP Settings (forwarded to PHP-FPM)
| Directive | Status | Notes |
|-----------|--------|-------|
| `php_value name value` | Full | Collected into `$htaccess_php_value` |
| `php_admin_value name value` | Full | Collected into `$htaccess_php_admin_value` |
| `php_flag name on/off` | Full | Collected into `$htaccess_php_value` |
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
| `<RequireAll>` / `<RequireAny>` / `<RequireNone>` | Full | Authorization containers |
| `<Directory>` / `<Location>` | Skip | Silently skipped (not per-dir context) |
| `<If>` / `<ElseIf>` / `<Else>` | Skip | Apache expressions not supported |

`<Limit>` recognizes GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH, TRACE, PROPFIND, PROPPATCH, COPY, MOVE, MKCOL, LOCK, UNLOCK. Nesting `<Limit>` inside `<Files>` is not supported (the inner block is silently skipped).

### Gracefully Ignored
These directives are recognized but silently ignored (correct behavior for nginx+FPM, or features that don't map to nginx):
- `AddHandler`, `SetHandler`, `RemoveHandler`
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
Full support for Apache server variables in `RewriteCond`, `RewriteRule` substitutions, and `SetEnvIf`:

```
REQUEST_URI, REQUEST_FILENAME, QUERY_STRING, HTTP_HOST,
HTTP_USER_AGENT, HTTP_REFERER, HTTP_COOKIE, HTTP_ACCEPT,
HTTP_ACCEPT_LANGUAGE, REMOTE_ADDR, REMOTE_HOST, REQUEST_METHOD,
SERVER_NAME, SERVER_PORT, SERVER_PROTOCOL, HTTPS, THE_REQUEST,
DOCUMENT_ROOT, REQUEST_SCHEME
```

Falls back to nginx variable lookup for any unrecognized variable name.

## Security

- Direct access to `.htaccess`, `.htpasswd`, `.htgroup`, and `.htdigest` files is blocked with 403.
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

The test suite is exercised against three nginx releases per CI run:

| Version | Status |
|---------|--------|
| 1.24.0 (oldest supported) | All 125 tests pass |
| 1.28.2 (default in Dockerfile) | All 125 tests pass |
| 1.30.1 (latest stable as of build) | All 125 tests pass |

Override the version at build time:
```bash
docker build --build-arg NGINX_VERSION=1.30.1 -t nginx-htaccess-test:1.30.1 .
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
