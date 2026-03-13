/*
 * ngx_http_htaccess_access.c - Access control and Basic authentication
 *
 * IP matching (exact, prefix, CIDR), Order/Allow/Deny logic,
 * Require directives, htpasswd-based Basic auth.
 */

#include "ngx_http_htaccess_module.h"
#include <crypt.h>
#include <arpa/inet.h>


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
 * Constant-time string comparison - prevents timing attacks on passwords
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_constant_time_strcmp(const u_char *a, const u_char *b)
{
    size_t alen, blen, i;
    u_char diff = 0;

    alen = ngx_strlen(a);
    blen = ngx_strlen(b);

    /* length mismatch - still compare full length to avoid timing leak */
    if (alen != blen) {
        /* compare against 'a' length to avoid revealing length difference */
        for (i = 0; i < alen; i++)
            diff |= a[i] ^ b[i % (blen ? blen : 1)];
        return 1;  /* not equal */
    }

    for (i = 0; i < alen; i++)
        diff |= a[i] ^ b[i];

    return diff != 0;
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
 * Access control - Order/Allow/Deny + Require
 *
 * Apache Order logic:
 *   deny,allow (default): allowed by default, deny overrides, allow overrides deny
 *   allow,deny: denied by default, allow overrides, deny overrides allow
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_access(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;
    ngx_int_t  allowed;
    ngx_str_t  cip;

    if (!h->has_acl && !h->require_denied && !h->require_granted)
        return NGX_OK;

    if (h->require_denied)  return NGX_HTTP_FORBIDDEN;
    if (h->require_granted) return NGX_OK;

    cip = r->connection->addr_text;

    if (h->access_order == HTA_ORDER_DENY_ALLOW) {
        allowed = 1;
        for (i = 0; i < h->nacl; i++)
            if (!h->acl[i].is_allow && hta_match_ip(&cip, &h->acl[i].value))
                allowed = 0;
        for (i = 0; i < h->nacl; i++)
            if (h->acl[i].is_allow && hta_match_ip(&cip, &h->acl[i].value))
                allowed = 1;
    } else {
        allowed = 0;
        for (i = 0; i < h->nacl; i++)
            if (h->acl[i].is_allow && hta_match_ip(&cip, &h->acl[i].value))
                allowed = 1;
        for (i = 0; i < h->nacl; i++)
            if (!h->acl[i].is_allow && hta_match_ip(&cip, &h->acl[i].value))
                allowed = 0;
    }

    return allowed ? NGX_OK : NGX_HTTP_FORBIDDEN;
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
 * Check <Files>/<FilesMatch> block access control
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_files_access(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i, j;
    ngx_str_t  basename;
    ngx_int_t  allowed;
    ngx_str_t  cip;

    if (h->nfiles_blocks == 0) return NGX_OK;

    basename = hta_uri_basename(&r->uri);
    if (basename.len == 0) return NGX_OK;

    cip = r->connection->addr_text;

    for (i = 0; i < h->nfiles_blocks; i++) {
        hta_files_block_t *fb = &h->files_blocks[i];

        if (!hta_files_match(fb, &basename)) continue;

        /* Check Require all denied/granted */
        if (fb->require_denied) return NGX_HTTP_FORBIDDEN;
        if (fb->require_granted) continue;

        /* Check Order/Allow/Deny */
        if (fb->has_acl) {
            if (fb->access_order == HTA_ORDER_DENY_ALLOW) {
                allowed = 1;
                for (j = 0; j < fb->nacl; j++)
                    if (!fb->acl[j].is_allow
                        && hta_match_ip(&cip, &fb->acl[j].value))
                        allowed = 0;
                for (j = 0; j < fb->nacl; j++)
                    if (fb->acl[j].is_allow
                        && hta_match_ip(&cip, &fb->acl[j].value))
                        allowed = 1;
            } else {
                allowed = 0;
                for (j = 0; j < fb->nacl; j++)
                    if (fb->acl[j].is_allow
                        && hta_match_ip(&cip, &fb->acl[j].value))
                        allowed = 1;
                for (j = 0; j < fb->nacl; j++)
                    if (!fb->acl[j].is_allow
                        && hta_match_ip(&cip, &fb->acl[j].value))
                        allowed = 0;
            }
            if (!allowed) return NGX_HTTP_FORBIDDEN;
        }
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

        if (!hta_files_match(fb, &basename)) continue;
        if (!fb->auth_basic) continue;

        /* Construct a temporary hta_parsed_t for auth check.
         * Heap-allocated — hta_parsed_t is too large for stack (~50KB). */
        {
        hta_parsed_t *tmp;
        ngx_uint_t    j;
        ngx_int_t     rc;

        tmp = ngx_pcalloc(r->pool, sizeof(hta_parsed_t));
        if (tmp == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        tmp->auth_basic = fb->auth_basic;
        tmp->auth_valid_user = fb->auth_valid_user;
        tmp->auth_name = fb->auth_name;
        tmp->auth_user_file = fb->auth_user_file;
        tmp->nauth_users = fb->nauth_users;
        for (j = 0; j < fb->nauth_users && j < HTA_MAX_USERS; j++)
            tmp->auth_users[j] = fb->auth_users[j];

        rc = hta_check_auth(r, tmp);
        if (rc != NGX_OK) return rc;
        }
    }
    return NGX_OK;
}


ngx_int_t
hta_check_auth(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_str_t  enc, dec;
    u_char    *colon;
    ngx_str_t  user, pass;

    if (!h->auth_basic) return NGX_OK;

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
    if (ngx_decode_base64(&dec, &enc) != NGX_OK) return NGX_HTTP_UNAUTHORIZED;
    dec.data[dec.len] = '\0';

    colon = (u_char *)ngx_strchr(dec.data, ':');
    if (colon == NULL) return NGX_HTTP_UNAUTHORIZED;

    user.data = dec.data; user.len = colon - dec.data;
    pass.data = colon + 1; pass.len = dec.len - user.len - 1;

    /* verify against htpasswd file */
    if (h->auth_user_file.len == 0) {
        /* no password file configured - cannot validate */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "htaccess: AuthUserFile not set but auth required");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
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
        if (fbuf == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

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
                    u_char     hbuf[256];

                    while (hlen > 0 && (hash[hlen-1] == '\r'
                                        || hash[hlen-1] == '\n'))
                        hlen--;
                    if (hlen < sizeof(hbuf)) {
                        u_char           pbuf[256];
                        struct crypt_data cd;

                        ngx_memcpy(hbuf, hash, hlen); hbuf[hlen] = '\0';
                        if (pass.len < sizeof(pbuf)) {
                            char *cr;
                            ngx_memcpy(pbuf, pass.data, pass.len);
                            pbuf[pass.len] = '\0';
                            cd.initialized = 0;
                            cr = crypt_r((char *)pbuf, (char *)hbuf, &cd);
                            if (cr && hta_constant_time_strcmp(
                                          (u_char *)cr, hbuf) == 0)
                                found = 1;
                            /* zero sensitive data */
                            hta_secure_zero(pbuf, sizeof(pbuf));
                            hta_secure_zero(&cd, sizeof(cd));
                        }
                    }
                    break;
                }
            }
            line = eol + 1;
        }

        if (!found) return NGX_HTTP_UNAUTHORIZED;
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
        if (!ok) return NGX_HTTP_UNAUTHORIZED;
    }

    return NGX_OK;
}
