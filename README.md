# ngx_http_htaccess_module

[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![nginx](https://img.shields.io/badge/nginx-1.24+-green.svg)](https://nginx.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()
[![Language](https://img.shields.io/badge/language-C-orange.svg)]()

A native C module for nginx that provides Apache-compatible `.htaccess` file support. Zero dependencies beyond PCRE and libc. No Lua, no OpenResty, no external interpreters.

> **Platform:** Linux only. The module uses `inotify` for file change monitoring and `crypt()` from glibc for password hashing. Windows and macOS are not supported.

## Why

Nginx deliberately does not support `.htaccess`. This is the correct architectural decision for pure nginx deployments. However, for **hosting providers** migrating from Apache/LiteSpeed, thousands of customer sites depend on `.htaccess` for URL rewriting, access control, and authentication. Converting each `.htaccess` to nginx config is impractical at scale.

This module solves that problem at the lowest possible overhead: native C, compiled directly into nginx, with aggressive caching and inotify-based invalidation.

## Performance

- Unlike Apache which re-reads `.htaccess` on every request, this module parses once and caches the result per-worker.
- When a `.htaccess` file changes, inotify triggers instant cache invalidation. No polling, no TTL expiration delays. Falls back to mtime-based stat() when inotify is unavailable.
- All parsed data lives in nginx memory pools, no malloc/free churn.
- Typical request adds <0.5ms even with deep directory traversal.

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
| `Allow from` / `Deny from` | Full | all, IP, prefix, CIDR notation (IPv4) |
| `Require all granted/denied` | Full | Apache 2.4 style |
| `Require ip` / `Require host` | Full | |
| `Require valid-user` / `Require user` | Full | |

### Authentication
| Directive | Status | Notes |
|-----------|--------|-------|
| `AuthType Basic` | Full | |
| `AuthName "realm"` | Full | |
| `AuthUserFile /path/.htpasswd` | Full | crypt() compatible (DES, MD5 $1$, SHA-256 $5$, SHA-512 $6$, bcrypt $2b$) |

### Response Headers
| Directive | Status | Notes |
|-----------|--------|-------|
| `Header [always] set name value` | Full | Replaces existing header |
| `Header [always] unset name` | Full | |
| `Header [always] append name value` | Full | |
| `Header [always] add name value` | Full | |
| `Header [always] merge name value` | Full | Deduplicates values |

### Caching
| Directive | Status | Notes |
|-----------|--------|-------|
| `ExpiresActive On/Off` | Full | |
| `ExpiresDefault "access plus N days"` | Full | Parses duration strings (years, months, weeks, days, hours, minutes, seconds) |
| `ExpiresByType mime/type "..."` | Full | Per-MIME-type expiration |

### Environment
| Directive | Status | Notes |
|-----------|--------|-------|
| `SetEnvIf attribute pattern env=value` | Full | Regex matching, sets nginx variables |

### Block Directives
| Directive | Status | Notes |
|-----------|--------|-------|
| `<IfModule mod_xxx>` | Full | Treated as always-present; negation (!) supported |
| `<Files "pattern">` | Full | Exact match, prefix/suffix wildcards |
| `<FilesMatch "regex">` | Full | PCRE regex against basename |
| `<Limit>` / `<LimitExcept>` | Full | Method-based blocks (content processed) |
| `<RequireAll>` / `<RequireAny>` / `<RequireNone>` | Full | Authorization containers |
| `<Directory>` / `<Location>` | Skip | Silently skipped (not per-dir context) |
| `<If>` / `<ElseIf>` / `<Else>` | Skip | Apache expressions not supported |

### Gracefully Ignored
These directives are recognized but silently ignored (correct behavior for nginx+FPM):
- `php_value`, `php_admin_value`, `php_flag`
- `AddHandler`, `SetHandler`, `RemoveHandler`
- `AddCharset`
- `Satisfy` (deprecated in Apache 2.4)
- `AddEncoding`, `AddLanguage`, `LanguagePriority`, `ForceLanguagePriority`
- `AddInputFilter`, `AddOutputFilter`, `AddOutputFilterByType`
- `SetInputFilter`, `SetOutputFilter`
- `RemoveType`
- `ServerSignature`, `FileETag`, `LimitRequestBody`
- `BrowserMatch`, `BrowserMatchNoCase`
- `SSLOptions`, `SSLRequireSSL`, `SSLRequire`
- `Action`, `SetEnvIfNoCase`, `PassEnv`, `UnsetEnv`
- `RequestHeader`
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
- File paths are validated within document root boundaries (path traversal prevention).
- `.htaccess` and `.htpasswd` files larger than 1MB are rejected.
- `Require valid-user` without `AuthUserFile` returns 500 instead of silently accepting.

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
           │   ├─ Apply SetEnvIf (set nginx variables)
           │   ├─ Apply DirectoryIndex
           │   ├─ Apply Redirect/RedirectMatch
           │   └─ Apply RewriteRules with RewriteConds
           │       ├─ Variable expansion (%{VAR})
           │       ├─ Backreference substitution ($1..$9)
           │       ├─ [E=var:val] environment variable setting
           │       └─ Chain/Skip/QSA/QSD/Redirect handling
           │
           ├─ ACCESS phase
           │   ├─ Block .htaccess/.htpasswd/.htgroup/.htdigest (403)
           │   ├─ Apply Order/Allow/Deny + Require
           │   ├─ Apply Basic Authentication (htpasswd with crypt)
           │   ├─ Apply <Files>/<FilesMatch> access control
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

80 automated tests covering all major features:

```bash
# Build and run tests in Docker
docker build -t nginx-htaccess-test .
docker run --rm nginx-htaccess-test
```

| Category | Tests | Coverage |
|----------|-------|----------|
| RewriteRule | 15 | Basic, backreferences, NC, R=301/302, F, G, QSA, QSD, chain, env |
| RewriteCond | 5 | HTTP_HOST, REQUEST_URI, negation, -f condition |
| Redirect | 6 | 301, 302, permanent, temp, gone (410), RedirectMatch |
| Access Control | 4 | Require all, Order Deny/Allow |
| Authentication | 5 | Basic auth, correct/wrong credentials, WWW-Authenticate |
| Headers | 4 | Header set, AddDefaultCharset, AddType |
| Expires | 4 | ExpiresActive, ExpiresDefault, ExpiresByType |
| DirectoryIndex | 2 | Index file serving |
| ErrorDocument | 2 | Custom 404, normal file passthrough |
| Files blocks | 3 | Files deny, Files allow, FilesMatch headers |
| SetEnvIf | 2 | Attribute matching, User-Agent |
| Security | 5 | .htaccess/.htpasswd/.htdigest blocking |
| CMS Compatibility | 30 | Parse + runtime tests for 10 CMS/frameworks |

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

### Feature Coverage

| Category | Coverage | Details |
|----------|----------|---------|
| Rewrite Engine (RewriteRule/Cond/Base) | 95% | All flags, backreferences, -f/-d/-l/-s/-x tests |
| Response Headers (set/unset/append/add/merge) | 85% | Full support |
| Caching (Expires/ExpiresByType) | 90% | All duration formats |
| Access Control (Order/Allow/Deny + Require) | 85% | IPv4 CIDR, host, all |
| Authentication (Basic + htpasswd) | 80% | DES, MD5, SHA-256, SHA-512, bcrypt |
| Block Directives (IfModule/Files/FilesMatch) | 90% | Nested blocks, negation |
| MIME Types (AddType/ForceType/AddDefaultCharset) | 90% | Multiple extensions |
| Environment (SetEnvIf) | 85% | Regex matching, nginx variables |

**Not applicable to nginx (correctly ignored):** `php_value`/`php_flag` (use php-fpm config), `AddHandler`/`SetHandler` (use FPM), `mod_deflate` (use `gzip on` in nginx.conf), `SSLRequireSSL` (use nginx ssl config), `mod_security` (use ngx_http_modsecurity_module).

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
