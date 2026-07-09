/*
 * ngx_http_htaccess_access.c - Access control and Basic authentication
 *
 * IP matching (exact, prefix, CIDR), Order/Allow/Deny logic,
 * Require directives, htpasswd-based Basic auth.
 */

#include "ngx_http_htaccess_module.h"
#include <crypt.h>
#include <arpa/inet.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * Secure memory zeroing - prevents compiler from optimizing away the clear
 * ═══════════════════════════════════════════════════════════════════════ */

static void
hta_secure_zero(void *ptr, size_t len)
{
    volatile u_char *p = (volatile u_char *)ptr;
    while (len--) *p++ = 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Constant-time byte buffer comparison (no NUL-terminator assumption)
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_constant_time_memcmp(const u_char *a, const u_char *b, size_t n)
{
    u_char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff != 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Apache APR1 MD5 crypt - $apr1$<salt>$<hash>
 *
 * Apache's variant of FreeBSD md5_crypt. The salt is at most 8 chars.
 * Reference: Apache's apr_md5_encode (apr-util crypt/apr_md5.c).
 * ═══════════════════════════════════════════════════════════════════════ */

/* APR1 uses a custom base64 alphabet (different ordering than RFC 4648) */
static const u_char hta_apr1_b64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
hta_apr1_to64(u_char *dst, ngx_uint_t v, ngx_int_t n)
{
    while (--n >= 0) {
        *dst++ = hta_apr1_b64[v & 0x3F];
        v >>= 6;
    }
}

/* Compute APR1 hash. Output: 22-char base64 portion (after "$apr1$<salt>$"). */
static void
hta_apr1_crypt(const u_char *pw, size_t pwlen,
               const u_char *salt, size_t saltlen,
               u_char out[22])
{
    ngx_md5_t ctx, ctx1;
    u_char    final[16];
    ngx_int_t i;
    size_t    pl;
    u_char   *p;

    if (saltlen > 8) saltlen = 8;

    /* "Then something really weird ..." - Poul-Henning Kamp's words */
    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, pw, pwlen);
    ngx_md5_update(&ctx, (u_char *) "$apr1$", 6);
    ngx_md5_update(&ctx, salt, saltlen);

    /* inner context: pw + salt + pw */
    ngx_md5_init(&ctx1);
    ngx_md5_update(&ctx1, pw, pwlen);
    ngx_md5_update(&ctx1, salt, saltlen);
    ngx_md5_update(&ctx1, pw, pwlen);
    ngx_md5_final(final, &ctx1);

    /* mix `final` into ctx in 16-byte chunks */
    for (pl = pwlen; pl > 0; pl -= (pl > 16 ? 16 : pl))
        ngx_md5_update(&ctx, final, pl > 16 ? 16 : pl);

    /* zero the password mixin slot */
    ngx_memzero(final, sizeof(final));

    /* bitwise weirdness: for each bit of pwlen, add a byte */
    for (i = (ngx_int_t) pwlen; i != 0; i >>= 1) {
        if (i & 1) ngx_md5_update(&ctx, final, 1);
        else       ngx_md5_update(&ctx, pw,    1);
    }

    ngx_md5_final(final, &ctx);

    /* 1000 rounds of stirring */
    for (i = 0; i < 1000; i++) {
        ngx_md5_init(&ctx1);
        if (i & 1) ngx_md5_update(&ctx1, pw, pwlen);
        else       ngx_md5_update(&ctx1, final, 16);
        if (i % 3) ngx_md5_update(&ctx1, salt, saltlen);
        if (i % 7) ngx_md5_update(&ctx1, pw, pwlen);
        if (i & 1) ngx_md5_update(&ctx1, final, 16);
        else       ngx_md5_update(&ctx1, pw, pwlen);
        ngx_md5_final(final, &ctx1);
    }

    /* encode the 16-byte digest in the canonical APR1 ordering */
    p = out;
    hta_apr1_to64(p, (final[ 0]<<16)|(final[ 6]<<8)|final[12], 4); p += 4;
    hta_apr1_to64(p, (final[ 1]<<16)|(final[ 7]<<8)|final[13], 4); p += 4;
    hta_apr1_to64(p, (final[ 2]<<16)|(final[ 8]<<8)|final[14], 4); p += 4;
    hta_apr1_to64(p, (final[ 3]<<16)|(final[ 9]<<8)|final[15], 4); p += 4;
    hta_apr1_to64(p, (final[ 4]<<16)|(final[10]<<8)|final[ 5], 4); p += 4;
    hta_apr1_to64(p, final[11], 2);

    hta_secure_zero(final, sizeof(final));
    hta_secure_zero(&ctx,  sizeof(ctx));
    hta_secure_zero(&ctx1, sizeof(ctx1));
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Dispatch password verification by hash format.
 *
 * Recognized formats (Apache htpasswd-compatible):
 *   $apr1$<salt>$<hash>   - Apache MD5 (custom impl, always available)
 *   $2a$ / $2b$ / $2y$    - bcrypt (via system crypt_r)
 *   $1$ / $5$ / $6$       - glibc MD5 / SHA-256 / SHA-512 (via crypt_r)
 *   {SHA}<base64>         - base64(SHA-1(plain))
 *   13-byte string        - legacy DES crypt (via crypt_r)
 *
 * Returns NGX_OK on match, NGX_DECLINED on mismatch, NGX_ERROR on internal
 * failure.
 *
 * All password bytes and intermediate buffers are zeroed before return.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_verify_password(u_char *plain, size_t plain_len,
                    u_char *hash,  size_t hash_len)
{
    ngx_int_t result = NGX_DECLINED;

    if (hash_len == 0) return NGX_DECLINED;

    /* ---- {SHA} ---- */
    if (hash_len >= 5 && ngx_strncmp(hash, "{SHA}", 5) == 0) {
        u_char    digest[20];
        u_char    expected[20];
        ngx_str_t enc, dec;
        ngx_sha1_t sha;

        ngx_sha1_init(&sha);
        ngx_sha1_update(&sha, plain, plain_len);
        ngx_sha1_final(digest, &sha);

        enc.data = hash + 5;
        enc.len  = hash_len - 5;
        dec.data = expected;
        dec.len  = sizeof(expected);
        if (ngx_decode_base64(&dec, &enc) != NGX_OK
            || dec.len != sizeof(expected))
        {
            hta_secure_zero(digest, sizeof(digest));
            return NGX_DECLINED;
        }
        if (hta_constant_time_memcmp(digest, expected, sizeof(digest)) == 0)
            result = NGX_OK;
        hta_secure_zero(digest,   sizeof(digest));
        hta_secure_zero(expected, sizeof(expected));
        return result;
    }

    /* ---- $apr1$<salt>$<hash> ---- */
    if (hash_len > 6 && ngx_strncmp(hash, "$apr1$", 6) == 0) {
        u_char    *salt = hash + 6;
        u_char    *salt_end = (u_char *) ngx_strchr(salt, '$');
        size_t     salt_len;
        u_char     computed[22];
        u_char    *expected_hash;
        size_t     expected_len;

        if (salt_end == NULL || salt_end >= hash + hash_len) return NGX_DECLINED;
        salt_len = salt_end - salt;
        if (salt_len > 8) salt_len = 8;
        expected_hash = salt_end + 1;
        expected_len  = (hash + hash_len) - expected_hash;
        if (expected_len != 22) return NGX_DECLINED;

        hta_apr1_crypt(plain, plain_len, salt, salt_len, computed);
        if (hta_constant_time_memcmp(computed, expected_hash, 22) == 0)
            result = NGX_OK;
        hta_secure_zero(computed, sizeof(computed));
        return result;
    }

    /* ---- crypt() compatible: $1$, $5$, $6$, $2a$/$2b$/$2y$, DES ---- */
    {
        u_char            pbuf[256];
        u_char            hbuf[256];
        struct crypt_data cd;
        char             *cr;

        if (plain_len >= sizeof(pbuf)) return NGX_DECLINED;
        if (hash_len  >= sizeof(hbuf)) return NGX_DECLINED;

        ngx_memcpy(pbuf, plain, plain_len);
        pbuf[plain_len] = '\0';
        ngx_memcpy(hbuf, hash, hash_len);
        hbuf[hash_len] = '\0';

        cd.initialized = 0;
        cr = crypt_r((char *) pbuf, (char *) hbuf, &cd);
        if (cr != NULL
            && ngx_strlen(cr) == hash_len
            && hta_constant_time_memcmp((u_char *) cr, hbuf, hash_len) == 0)
        {
            result = NGX_OK;
        }
        hta_secure_zero(pbuf, sizeof(pbuf));
        hta_secure_zero(hbuf, sizeof(hbuf));
        hta_secure_zero(&cd,  sizeof(cd));
        return result;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * IP matching - exact, prefix, CIDR
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_match_ip(ngx_str_t *client, ngx_str_t *pat)
{
    u_char *slash;

    if (ngx_strcasecmp(pat->data, (u_char *)"all") == 0) return 1;

    /* exact match */
    if (pat->len == client->len
        && ngx_strncmp(pat->data, client->data, pat->len) == 0)
    {
        return 1;
    }

    /* prefix (e.g., "192.168.") */
    if (pat->len > 0 && pat->data[pat->len - 1] == '.'
        && client->len >= pat->len
        && ngx_strncmp(pat->data, client->data, pat->len) == 0)
    {
        return 1;
    }

    /* CIDR - IPv4 (e.g., "10.0.0.0/8") and IPv6 (e.g., "::1/128") */
    slash = (u_char *)ngx_strchr(pat->data, '/');
    if (slash) {
        ngx_uint_t bits = ngx_atoi(slash + 1,
                                    pat->len - (slash + 1 - pat->data));
        u_char     ibuf[64], cbuf[64];
        ngx_uint_t ilen = slash - pat->data;

        if (ilen < 64 && client->len < 64) {
            ngx_memcpy(ibuf, pat->data, ilen); ibuf[ilen] = '\0';
            ngx_memcpy(cbuf, client->data, client->len);
            cbuf[client->len] = '\0';

            if (bits <= 128) {
                /* Try IPv4 first, then IPv6 — bits alone can't determine family
                 * (e.g., fe80::/10 has bits=10 which is also valid for IPv4) */
                struct in_addr ca, pa;
                if (bits <= 32
                    && inet_pton(AF_INET, (char *)ibuf, &pa) == 1
                    && inet_pton(AF_INET, (char *)cbuf, &ca) == 1)
                {
                    uint32_t mask;
                    if (bits == 0)       mask = 0;
                    else if (bits == 32) mask = htonl(0xFFFFFFFF);
                    else                 mask = htonl(~((1U << (32 - bits)) - 1));
                    if ((ca.s_addr & mask) == (pa.s_addr & mask)) return 1;
                } else {
                    /* IPv6 CIDR */
                    struct in6_addr ca6, pa6;
                    if (inet_pton(AF_INET6, (char *)ibuf, &pa6) == 1
                        && inet_pton(AF_INET6, (char *)cbuf, &ca6) == 1)
                    {
                        ngx_uint_t j, full = bits / 8, rem = bits % 8;
                        int        ok = 1;
                        for (j = 0; j < 16 && ok; j++) {
                            uint8_t m = (j < full)  ? 0xFF
                                      : (j == full) ? (rem ? (0xFF << (8 - rem)) & 0xFF : 0)
                                                    : 0;
                            if ((ca6.s6_addr[j] & m) != (pa6.s6_addr[j] & m))
                                ok = 0;
                        }
                        if (ok) return 1;
                    }
                }
            }
        }
    }

    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Is the client connecting from the local machine (Require local)?
 * Matches IPv4 loopback (127.0.0.0/8), IPv6 loopback (::1) and unix sockets.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_ip_is_local(ngx_str_t *cip)
{
    if (cip->len >= 4 && ngx_strncmp(cip->data, "127.", 4) == 0) return 1;
    if (cip->len == 3 && ngx_strncmp(cip->data, "::1", 3) == 0) return 1;
    if (cip->len >= 5 && ngx_strncmp(cip->data, "unix:", 5) == 0) return 1;
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Is an nginx environment variable set and non-empty? Backs "env=" tokens in
 * Allow/Deny and "Require env". The variable must be declared in nginx.conf
 * (set/map) and is typically populated by SetEnvIf/BrowserMatch.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_env_is_set(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_str_t                  lname;
    ngx_uint_t                 k, hash;
    ngx_http_variable_value_t *vv;

    if (name->len == 0) return 0;

    lname.len  = name->len;
    lname.data = ngx_pnalloc(r->pool, lname.len);
    if (lname.data == NULL) return 0;
    for (k = 0; k < lname.len; k++)
        lname.data[k] = ngx_tolower(name->data[k]);

    hash = ngx_hash_key(lname.data, lname.len);
    vv = ngx_http_get_variable(r, &lname, hash);
    return (vv && !vv->not_found && vv->len > 0) ? 1 : 0;
}


/* Match one ACL/Require entry against the client. "env=NAME" tokens test an
 * environment variable; everything else is an IP/CIDR/prefix match. */
static ngx_int_t
hta_acl_entry_match(ngx_http_request_t *r, ngx_str_t *cip, hta_access_t *a)
{
    if (a->value.len > 4 && ngx_strncmp(a->value.data, "env=", 4) == 0) {
        ngx_str_t name;
        name.data = a->value.data + 4;
        name.len  = a->value.len - 4;
        return hta_env_is_set(r, &name);
    }
    return hta_match_ip(cip, &a->value);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Shared access evaluator - mod_access_compat (Allow/Deny/Order) combined with
 * mod_authz_host style Require ip/host/env/local.
 *
 * Apache Order logic (mod_access_compat):
 *   deny,allow (default): allowed by default, deny overrides, allow overrides deny
 *   allow,deny: denied by default, allow overrides, deny overrides allow
 *
 * Require ip/host/env/local are authorization requirements: when present, the
 * client MUST match at least one of them (RequireAny among themselves), else it
 * is denied. This closes the fail-open hole where a standalone "Require ip"
 * used to grant everyone under the default deny,allow order.
 *
 * "Require all granted" waives the host requirement but does NOT override an
 * explicit Deny; "Require all denied" and unsupported Require providers fail
 * closed.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_eval_acl(ngx_http_request_t *r, hta_access_t *acl, ngx_uint_t nacl,
    ngx_uint_t order, unsigned has_compat, unsigned has_require_host,
    unsigned require_local, unsigned require_failed,
    unsigned require_granted, unsigned require_denied)
{
    ngx_uint_t i;
    ngx_int_t  compat_ok, host_ok;
    ngx_str_t  cip;

    if (require_denied) return NGX_HTTP_FORBIDDEN;
    if (require_failed) return NGX_HTTP_FORBIDDEN;

    cip = r->connection->addr_text;

    /* mod_access_compat Allow/Deny over non-Require entries */
    compat_ok = 1;
    if (has_compat) {
        if (order == HTA_ORDER_DENY_ALLOW) {
            compat_ok = 1;
            for (i = 0; i < nacl; i++)
                if (!acl[i].is_require && !acl[i].is_allow
                    && hta_acl_entry_match(r, &cip, &acl[i]))
                    compat_ok = 0;
            for (i = 0; i < nacl; i++)
                if (!acl[i].is_require && acl[i].is_allow
                    && hta_acl_entry_match(r, &cip, &acl[i]))
                    compat_ok = 1;
        } else {
            compat_ok = 0;
            for (i = 0; i < nacl; i++)
                if (!acl[i].is_require && acl[i].is_allow
                    && hta_acl_entry_match(r, &cip, &acl[i]))
                    compat_ok = 1;
            for (i = 0; i < nacl; i++)
                if (!acl[i].is_require && !acl[i].is_allow
                    && hta_acl_entry_match(r, &cip, &acl[i]))
                    compat_ok = 0;
        }
    }

    /* Require ip/host/env/local: client must match at least one (RequireAny) */
    host_ok = 1;
    if (require_granted) {
        host_ok = 1;
    } else if (has_require_host || require_local) {
        host_ok = 0;
        if (require_local && hta_ip_is_local(&cip)) host_ok = 1;
        if (!host_ok) {
            for (i = 0; i < nacl; i++)
                if (acl[i].is_require
                    && hta_acl_entry_match(r, &cip, &acl[i]))
                { host_ok = 1; break; }
        }
    }

    return (compat_ok && host_ok) ? NGX_OK : NGX_HTTP_FORBIDDEN;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Access control - Order/Allow/Deny + Require (top-level scope)
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_access(ngx_http_request_t *r, hta_parsed_t *h)
{
    if (!h->has_acl && !h->has_require_host && !h->require_local
        && !h->require_denied && !h->require_granted && !h->require_failed)
        return NGX_OK;

    return hta_eval_acl(r, h->acl, h->nacl, h->access_order,
        h->has_acl, h->has_require_host, h->require_local, h->require_failed,
        h->require_granted, h->require_denied);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * htpasswd file cache - one stat() per request instead of open+read
 *
 * Returns pointer to NUL-terminated file content (persistent, not r->pool).
 * Returns NULL on error.  *out_len is set to content length.
 * ═══════════════════════════════════════════════════════════════════════ */

static const u_char *
hta_passwd_get(ngx_http_hta_main_conf_t *mc, ngx_str_t *path,
    size_t *out_len, ngx_log_t *log)
{
    ngx_uint_t       i, slot;
    ngx_file_info_t  fi;
    time_t           mtime;
    ngx_fd_t         fd;
    off_t            fsz;
    ssize_t          nr;
    hta_passwd_entry_t *e;

    if (path->len == 0 || path->len >= HTA_MAX_PATH) return NULL;

    /* stat the file to get current mtime */
    if (ngx_file_info(path->data, &fi) != 0)  return NULL;
    mtime = ngx_file_mtime(&fi);
    fsz   = ngx_file_size(&fi);
    if (fsz <= 0 || fsz > 1024 * 1024) return NULL;

    /* lookup in cache */
    for (i = 0; i < mc->npasswd; i++) {
        if (mc->passwd[i].pathlen == path->len
            && ngx_memcmp(mc->passwd[i].path, path->data, path->len) == 0)
        {
            if (mc->passwd[i].mtime == mtime && mc->passwd[i].content) {
                /* cache hit */
                *out_len = mc->passwd[i].content_len;
                return mc->passwd[i].content;
            }
            /* mtime changed - invalidate */
            if (mc->passwd[i].pool) {
                ngx_destroy_pool(mc->passwd[i].pool);
                mc->passwd[i].pool    = NULL;
                mc->passwd[i].content = NULL;
            }
            slot = i;
            goto load;
        }
    }

    /* not found - evict oldest if full */
    if (mc->npasswd >= HTA_PASSWD_SLOTS) {
        if (mc->passwd[0].pool) ngx_destroy_pool(mc->passwd[0].pool);
        ngx_memmove(&mc->passwd[0], &mc->passwd[1],
                     sizeof(hta_passwd_entry_t) * (HTA_PASSWD_SLOTS - 1));
        mc->npasswd--;
    }
    slot = mc->npasswd;
    ngx_memzero(&mc->passwd[slot], sizeof(hta_passwd_entry_t));
    ngx_memcpy(mc->passwd[slot].path, path->data, path->len);
    mc->passwd[slot].path[path->len] = '\0';
    mc->passwd[slot].pathlen = path->len;
    mc->npasswd++;

load:
    e = &mc->passwd[slot];

    /* read file into per-entry pool */
    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) return NULL;

    e->pool = ngx_create_pool((size_t)fsz + 256, log);
    if (e->pool == NULL) { ngx_close_file(fd); return NULL; }

    e->content = ngx_palloc(e->pool, (size_t)fsz + 1);
    if (e->content == NULL) {
        ngx_close_file(fd);
        ngx_destroy_pool(e->pool); e->pool = NULL;
        return NULL;
    }

    nr = ngx_read_fd(fd, e->content, (size_t)fsz);
    ngx_close_file(fd);

    if (nr <= 0) {
        ngx_destroy_pool(e->pool); e->pool = NULL;
        e->content = NULL;
        return NULL;
    }

    e->content[nr] = '\0';
    e->content_len  = (size_t)nr;
    e->mtime        = mtime;

    *out_len = e->content_len;
    return e->content;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Extract basename from URI
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_str_t
hta_uri_basename(ngx_str_t *uri)
{
    ngx_str_t bname;
    u_char *p;

    bname = *uri;
    for (p = uri->data + uri->len; p > uri->data; ) {
        p--;
        if (*p == '/') {
            bname.data = p + 1;
            bname.len = (uri->data + uri->len) - (p + 1);
            break;
        }
    }
    return bname;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Match filename against <Files>/<FilesMatch> pattern
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_files_match(hta_files_block_t *fb, ngx_str_t *basename)
{
    if (basename->len == 0) return 0;

    if (fb->is_regex && fb->regex) {
        return ngx_regex_exec(fb->regex, basename, NULL, 0) >= 0;
    }

    /* exact match */
    if (fb->pattern.len == basename->len
        && ngx_strncasecmp(fb->pattern.data, basename->data,
                           basename->len) == 0)
    {
        return 1;
    }

    /* simple wildcard: ".ht*" or "*.ext" */
    if (fb->pattern.len > 1 && fb->pattern.data[fb->pattern.len - 1] == '*') {
        ngx_uint_t plen = fb->pattern.len - 1;
        if (basename->len >= plen
            && ngx_strncasecmp(basename->data, fb->pattern.data, plen) == 0)
        {
            return 1;
        }
    }
    if (fb->pattern.len > 1 && fb->pattern.data[0] == '*') {
        ngx_uint_t slen = fb->pattern.len - 1;
        if (basename->len >= slen
            && ngx_strncasecmp(basename->data + basename->len - slen,
                               fb->pattern.data + 1, slen) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SSLRequireSSL / SSLRequire - require HTTPS connection.
 *
 * Also accepts X-Forwarded-Proto: https when behind a TLS-terminating proxy.
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_ssl(ngx_http_request_t *r, hta_parsed_t *h, ngx_uint_t trust_proxy)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *hdr;
    ngx_uint_t        i;

    if (!h->ssl_required) return NGX_OK;

#if (NGX_HTTP_SSL)
    if (r->connection->ssl) return NGX_OK;
#endif

    /* X-Forwarded-Proto is client-controllable, so only trust it when the
     * operator has opted in with `htaccess_trust_proxy on;` (i.e. nginx sits
     * behind a TLS-terminating proxy that overwrites the header). Without this
     * a direct client could spoof https and bypass SSLRequireSSL. */
    if (!trust_proxy) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "htaccess: SSLRequireSSL denied non-HTTPS request");
        return NGX_HTTP_FORBIDDEN;
    }

    /* honor X-Forwarded-Proto: https for deployments behind a TLS proxy */
    part = &r->headers_in.headers.part;
    hdr  = part->elts;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            hdr  = part->elts;
            i = 0;
        }
        if (hdr[i].key.len == sizeof("X-Forwarded-Proto") - 1
            && ngx_strncasecmp(hdr[i].key.data,
                (u_char *)"X-Forwarded-Proto",
                sizeof("X-Forwarded-Proto") - 1) == 0
            && hdr[i].value.len == 5
            && ngx_strncasecmp(hdr[i].value.data,
                (u_char *)"https", 5) == 0)
        {
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "htaccess: SSLRequireSSL denied non-HTTPS request");
    return NGX_HTTP_FORBIDDEN;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Check <Files>/<FilesMatch> block access control
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_files_access(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;
    ngx_str_t  basename;

    if (h->nfiles_blocks == 0) return NGX_OK;

    basename = hta_uri_basename(&r->uri);
    if (basename.len == 0) return NGX_OK;

    for (i = 0; i < h->nfiles_blocks; i++) {
        hta_files_block_t *fb = &h->files_blocks[i];
        ngx_int_t          rc;

        if (!hta_files_match(fb, &basename)) continue;

        if (!fb->has_acl && !fb->has_require_host && !fb->require_local
            && !fb->require_denied && !fb->require_granted
            && !fb->require_failed)
            continue;

        rc = hta_eval_acl(r, fb->acl, fb->nacl, fb->access_order,
            fb->has_acl, fb->has_require_host, fb->require_local,
            fb->require_failed, fb->require_granted, fb->require_denied);
        if (rc != NGX_OK) return rc;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Check <Files>/<FilesMatch> block authentication
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_files_auth(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;
    ngx_str_t  basename;

    if (h->nfiles_blocks == 0) return NGX_OK;

    basename = hta_uri_basename(&r->uri);
    if (basename.len == 0) return NGX_OK;

    for (i = 0; i < h->nfiles_blocks; i++) {
        hta_files_block_t *fb = &h->files_blocks[i];
        unsigned           block_sets_type;
        unsigned           eff_basic, eff_unsupported;
        unsigned           has_req;

        if (!hta_files_match(fb, &basename)) continue;

        /* A <Files>/<FilesMatch> block inherits AuthType/AuthName/AuthUserFile/
         * AuthGroupFile from the enclosing scope (Apache behavior). Without this
         * a per-file "Require valid-user"/"Require user" was silently ignored
         * when AuthType lived at the top level (auth bypass). */
        block_sets_type = fb->auth_basic || fb->auth_type_unsupported;
        eff_basic       = block_sets_type ? fb->auth_basic : h->auth_basic;
        eff_unsupported = block_sets_type ? fb->auth_type_unsupported
                                          : h->auth_type_unsupported;
        has_req = fb->auth_valid_user || fb->nauth_users
                  || fb->nrequire_groups;

        /* only engage auth when the block adds an auth requirement or sets its
         * own AuthType; the top-level auth is checked separately */
        if (!has_req && !block_sets_type) continue;

        {
        hta_parsed_t *tmp;
        ngx_uint_t    j;
        ngx_int_t     rc;

        tmp = ngx_pcalloc(r->pool, sizeof(hta_parsed_t));
        if (tmp == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        tmp->auth_basic = eff_basic;
        tmp->auth_type_unsupported = eff_unsupported;
        tmp->auth_valid_user = fb->auth_valid_user;
        tmp->auth_name = fb->auth_name.len ? fb->auth_name : h->auth_name;
        tmp->auth_user_file = fb->auth_user_file.len ? fb->auth_user_file
                                                     : h->auth_user_file;
        tmp->auth_group_file = fb->auth_group_file.len ? fb->auth_group_file
                                                       : h->auth_group_file;
        tmp->nauth_users = fb->nauth_users;
        for (j = 0; j < fb->nauth_users && j < HTA_MAX_USERS; j++)
            tmp->auth_users[j] = fb->auth_users[j];
        tmp->nrequire_groups = fb->nrequire_groups;
        for (j = 0; j < fb->nrequire_groups && j < HTA_MAX_GROUPS; j++)
            tmp->require_groups[j] = fb->require_groups[j];

        rc = hta_check_auth(r, tmp);
        if (rc != NGX_OK) return rc;
        }
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Does the request method match the limit block?
 *
 * <Limit M1 M2 ...>     matches iff r->method is in {M1, M2, ...}
 * <LimitExcept M1 M2>   matches iff r->method is NOT in {M1, M2, ...}
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_limit_matches(ngx_http_request_t *r, hta_limit_block_t *lb)
{
    ngx_uint_t methods = lb->methods;
    ngx_uint_t hit;

    /* Apache: constraining GET also constrains HEAD. Fold HEAD into the mask so
     * a "<Limit GET>" IP/auth gate cannot be bypassed with a HEAD request, and
     * "<LimitExcept GET>" does not wrongly block HEAD health checks. */
    if (methods & NGX_HTTP_GET) methods |= NGX_HTTP_HEAD;

    hit = (r->method & methods) != 0;
    return lb->is_except ? !hit : hit;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Check <Limit>/<LimitExcept> block access control (Order/Allow/Deny/Require)
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_limit_access(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;

    if (h->nlimit_blocks == 0) return NGX_OK;

    for (i = 0; i < h->nlimit_blocks; i++) {
        hta_limit_block_t *lb = &h->limit_blocks[i];
        ngx_int_t          rc;

        if (!hta_limit_matches(r, lb)) continue;

        if (!lb->has_acl && !lb->has_require_host && !lb->require_local
            && !lb->require_denied && !lb->require_granted
            && !lb->require_failed)
            continue;

        rc = hta_eval_acl(r, lb->acl, lb->nacl, lb->access_order,
            lb->has_acl, lb->has_require_host, lb->require_local,
            lb->require_failed, lb->require_granted, lb->require_denied);
        if (rc != NGX_OK) return rc;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Check <Limit>/<LimitExcept> block authentication
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_limit_auth(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;

    if (h->nlimit_blocks == 0) return NGX_OK;

    for (i = 0; i < h->nlimit_blocks; i++) {
        hta_limit_block_t *lb = &h->limit_blocks[i];
        hta_parsed_t      *tmp;
        ngx_uint_t         j;
        ngx_int_t          rc;
        unsigned           block_sets_type, eff_basic, eff_unsupported, has_req;

        if (!hta_limit_matches(r, lb)) continue;

        /* inherit AuthType/AuthUserFile from the enclosing scope, same as
         * <Files> - a per-method "Require valid-user" must not be dropped */
        block_sets_type = lb->auth_basic || lb->auth_type_unsupported;
        eff_basic       = block_sets_type ? lb->auth_basic : h->auth_basic;
        eff_unsupported = block_sets_type ? lb->auth_type_unsupported
                                          : h->auth_type_unsupported;
        has_req = lb->auth_valid_user || lb->nauth_users
                  || lb->nrequire_groups;

        if (!has_req && !block_sets_type) continue;

        tmp = ngx_pcalloc(r->pool, sizeof(hta_parsed_t));
        if (tmp == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        tmp->auth_basic = eff_basic;
        tmp->auth_type_unsupported = eff_unsupported;
        tmp->auth_valid_user = lb->auth_valid_user;
        tmp->auth_name = lb->auth_name.len ? lb->auth_name : h->auth_name;
        tmp->auth_user_file = lb->auth_user_file.len ? lb->auth_user_file
                                                     : h->auth_user_file;
        tmp->auth_group_file = lb->auth_group_file.len ? lb->auth_group_file
                                                       : h->auth_group_file;
        tmp->nauth_users = lb->nauth_users;
        for (j = 0; j < lb->nauth_users && j < HTA_MAX_USERS; j++)
            tmp->auth_users[j] = lb->auth_users[j];
        tmp->nrequire_groups = lb->nrequire_groups;
        for (j = 0; j < lb->nrequire_groups && j < HTA_MAX_GROUPS; j++)
            tmp->require_groups[j] = lb->require_groups[j];

        rc = hta_check_auth(r, tmp);
        if (rc != NGX_OK) return rc;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Script-execution kill-switch (SetHandler none / RemoveHandler .php /
 * php_flag engine off). nginx routes *.php to FPM in a separate location, so we
 * cannot un-route it; instead we deny the request in the access phase, which
 * prevents an uploaded shell from executing. NOTE: this only fires if the
 * htaccess module is enabled in the location that actually serves the scripts
 * (e.g. `location ~ \.php$`), since that is where the request lands.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_name_is_script(ngx_str_t *bn)
{
    static const char *exts[] = {
        ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8",
        ".phps", ".pht", ".phar", NULL
    };
    ngx_uint_t i;

    for (i = 0; exts[i]; i++) {
        size_t el = ngx_strlen(exts[i]);
        if (bn->len >= el
            && ngx_strncasecmp(bn->data + bn->len - el,
                               (u_char *) exts[i], el) == 0)
            return 1;
    }
    return 0;
}

ngx_int_t
hta_check_exec(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_str_t  bn;
    ngx_uint_t i;

    if (!h->exec_disabled && h->nfiles_blocks == 0) return NGX_OK;

    bn = hta_uri_basename(&r->uri);
    if (bn.len == 0) return NGX_OK;

    /* per-block: a matching <Files>/<FilesMatch> with the handler removed
     * blocks execution regardless of extension (the block targets those files) */
    for (i = 0; i < h->nfiles_blocks; i++) {
        hta_files_block_t *fb = &h->files_blocks[i];
        if (fb->exec_disabled && hta_files_match(fb, &bn)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "htaccess: script execution disabled for \"%V\"", &r->uri);
            return NGX_HTTP_FORBIDDEN;
        }
    }

    /* directory-wide engine off: block known script extensions */
    if (h->exec_disabled && hta_name_is_script(&bn)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "htaccess: script execution disabled for \"%V\"", &r->uri);
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


ngx_int_t
hta_check_auth(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_str_t  enc, dec;
    u_char    *colon;
    ngx_str_t  user, pass;
    ngx_int_t  result;

    /* AuthType set to an unsupported scheme (Digest, etc.): fail closed rather
     * than silently serving the protected resource (Apache returns 500). */
    if (h->auth_type_unsupported) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "htaccess: unsupported AuthType (only Basic is implemented), "
            "denying access");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!h->auth_basic) {
        /* A Require user/group/valid-user with no usable AuthType is a
         * misconfiguration; Apache fails closed with 500. Do the same instead
         * of granting access (the old behavior was a silent auth bypass). */
        if (h->auth_valid_user || h->nauth_users > 0
            || h->nrequire_groups > 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "htaccess: Require user/group/valid-user without "
                "\"AuthType Basic\", denying access");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return NGX_OK;
    }

    if (r->headers_in.authorization == NULL) {
        ngx_table_elt_t *www = ngx_list_push(&r->headers_out.headers);
        if (www == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        www->hash = 1;
        ngx_str_set(&www->key, "WWW-Authenticate");
        if (h->auth_name.len > 0) {
            u_char *realm = ngx_pnalloc(r->pool, 16 + h->auth_name.len);
            if (realm) {
                www->value.len = ngx_sprintf(realm, "Basic realm=\"%V\"",
                                              &h->auth_name) - realm;
                www->value.data = realm;
            }
        } else {
            ngx_str_set(&www->value, "Basic realm=\"Restricted\"");
        }
        return NGX_HTTP_UNAUTHORIZED;
    }

    enc = r->headers_in.authorization->value;
    if (enc.len < 6 || ngx_strncasecmp(enc.data, (u_char *)"Basic ", 6) != 0)
        return NGX_HTTP_UNAUTHORIZED;

    enc.data += 6; enc.len -= 6;

    dec.len = ngx_base64_decoded_length(enc.len);
    dec.data = ngx_pnalloc(r->pool, dec.len + 1);
    if (dec.data == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ngx_decode_base64(&dec, &enc) != NGX_OK) {
        hta_secure_zero(dec.data, dec.len + 1);
        return NGX_HTTP_UNAUTHORIZED;
    }
    dec.data[dec.len] = '\0';

    colon = (u_char *)ngx_strchr(dec.data, ':');
    if (colon == NULL) {
        hta_secure_zero(dec.data, dec.len + 1);
        return NGX_HTTP_UNAUTHORIZED;
    }

    user.data = dec.data; user.len = colon - dec.data;
    pass.data = colon + 1; pass.len = dec.len - user.len - 1;

    /* defensive cap: APR1's bit-shift loop assumes pwlen fits in ngx_int_t */
    if (pass.len > 1024) {
        hta_secure_zero(dec.data, dec.len + 1);
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Anything below this point exits via `goto done` so the decoded
     * "user:pass" plaintext gets zeroed on every path. */
    result = NGX_OK;

    /* verify against htpasswd file */
    if (h->auth_user_file.len == 0) {
        /* no password file configured - cannot validate */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "htaccess: AuthUserFile not set but auth required");
        result = NGX_HTTP_INTERNAL_SERVER_ERROR; goto done;
    }

    /* Security: reject path traversal in AuthUserFile */
    {
        u_char *pp, *pe;
        pp = h->auth_user_file.data;
        pe = pp + h->auth_user_file.len;
        while (pp < pe) {
            if (*pp == '.' && pp + 1 < pe && *(pp + 1) == '.') {
                if ((pp == h->auth_user_file.data || *(pp - 1) == '/')
                    && (pp + 2 >= pe || *(pp + 2) == '/'))
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "htaccess: path traversal in AuthUserFile \"%V\"",
                        &h->auth_user_file);
                    result = NGX_HTTP_INTERNAL_SERVER_ERROR; goto done;
                }
            }
            pp++;
        }
    }
    {
        ngx_http_hta_main_conf_t *mc;
        const u_char             *fbuf;
        size_t                    fsz;
        unsigned                  found;
        u_char                   *line, *fend;

        mc = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
        fbuf = hta_passwd_get(mc, &h->auth_user_file, &fsz,
                               r->connection->log);
        if (fbuf == NULL) {
            result = NGX_HTTP_INTERNAL_SERVER_ERROR; goto done;
        }

        found = 0;
        line = (u_char *)fbuf;
        fend = (u_char *)fbuf + fsz;

        while (line < fend) {
            u_char *eol = (u_char *)ngx_strchr(line, '\n');
            u_char *fc;

            if (eol == NULL) eol = fend;
            fc = (u_char *)ngx_strchr(line, ':');
            if (fc && fc < eol) {
                ngx_uint_t ulen = fc - line;
                if (ulen == user.len
                    && ngx_strncmp(line, user.data, user.len) == 0)
                {
                    u_char    *hash = fc + 1;
                    ngx_uint_t hlen = eol - hash;

                    while (hlen > 0 && (hash[hlen-1] == '\r'
                                        || hash[hlen-1] == '\n'))
                        hlen--;
                    if (hta_verify_password(pass.data, pass.len,
                                            hash, hlen) == NGX_OK)
                        found = 1;
                    break;
                }
            }
            line = eol + 1;
        }

        if (!found) { result = NGX_HTTP_UNAUTHORIZED; goto done; }
    }

    /* check Require user list */
    if (h->nauth_users > 0) {
        unsigned ok = 0;
        ngx_uint_t i;
        for (i = 0; i < h->nauth_users; i++) {
            if (h->auth_users[i].len == user.len &&
                ngx_strncmp(h->auth_users[i].data, user.data, user.len) == 0)
            { ok = 1; break; }
        }
        if (!ok) { result = NGX_HTTP_UNAUTHORIZED; goto done; }
    }

    /* check Require group list against AuthGroupFile */
    if (h->nrequire_groups > 0) {
        if (h->auth_group_file.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "htaccess: Require group used without AuthGroupFile");
            result = NGX_HTTP_INTERNAL_SERVER_ERROR; goto done;
        }

        /* path-traversal guard, mirrors the AuthUserFile check above */
        {
            u_char *pp, *pe;
            pp = h->auth_group_file.data;
            pe = pp + h->auth_group_file.len;
            while (pp < pe) {
                if (*pp == '.' && pp + 1 < pe && *(pp + 1) == '.'
                    && (pp == h->auth_group_file.data || *(pp - 1) == '/')
                    && (pp + 2 >= pe || *(pp + 2) == '/'))
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "htaccess: path traversal in AuthGroupFile \"%V\"",
                        &h->auth_group_file);
                    result = NGX_HTTP_INTERNAL_SERVER_ERROR; goto done;
                }
                pp++;
            }
        }

        {
            ngx_http_hta_main_conf_t *mc;
            const u_char             *gbuf;
            size_t                    gsz;
            u_char                   *line, *gend;
            unsigned                  in_group = 0;

            mc = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
            gbuf = hta_passwd_get(mc, &h->auth_group_file, &gsz,
                                   r->connection->log);
            if (gbuf == NULL) {
                result = NGX_HTTP_INTERNAL_SERVER_ERROR; goto done;
            }

            line = (u_char *)gbuf;
            gend = (u_char *)gbuf + gsz;

            /* htgroup format (one line per group):
             *   groupname: user1 user2 user3
             */
            while (line < gend && !in_group) {
                u_char *eol = (u_char *)ngx_strchr(line, '\n');
                u_char *colon;
                ngx_str_t gname;

                if (eol == NULL || eol > gend) eol = gend;
                colon = (u_char *)ngx_strchr(line, ':');
                if (colon == NULL || colon >= eol) { line = eol + 1; continue; }

                gname.data = line;
                gname.len  = colon - line;
                /* trim trailing spaces on the group name */
                while (gname.len > 0 && (gname.data[gname.len - 1] == ' '
                                         || gname.data[gname.len - 1] == '\t'))
                    gname.len--;

                /* is this one of our required groups? */
                {
                    ngx_uint_t gi;
                    unsigned   matches_req = 0;
                    for (gi = 0; gi < h->nrequire_groups; gi++) {
                        if (h->require_groups[gi].len == gname.len
                            && ngx_strncmp(h->require_groups[gi].data,
                                           gname.data, gname.len) == 0)
                        {
                            matches_req = 1; break;
                        }
                    }
                    if (!matches_req) { line = eol + 1; continue; }
                }

                /* walk the member list */
                {
                    u_char *mp = colon + 1, *mend = eol;
                    while (mp < mend) {
                        u_char *ms;
                        ngx_uint_t mlen;

                        while (mp < mend && (*mp == ' ' || *mp == '\t'
                                             || *mp == '\r')) mp++;
                        if (mp >= mend) break;
                        ms = mp;
                        while (mp < mend && *mp != ' ' && *mp != '\t'
                               && *mp != '\r') mp++;
                        mlen = mp - ms;
                        if (mlen == user.len
                            && ngx_strncmp(ms, user.data, user.len) == 0)
                        {
                            in_group = 1; break;
                        }
                    }
                }
                line = eol + 1;
            }

            if (!in_group) {
                result = NGX_HTTP_UNAUTHORIZED; goto done;
            }
        }
    }

done:
    /* zero the decoded "user:pass" plaintext so it does not linger in
     * the request pool until the request is destroyed */
    hta_secure_zero(dec.data, dec.len + 1);
    return result;
}
