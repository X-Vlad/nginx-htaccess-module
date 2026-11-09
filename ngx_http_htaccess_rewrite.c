/*
 * ngx_http_htaccess_rewrite.c - Rewrite engine
 *
 * Variable expansion, backreference substitution, condition evaluation,
 * RewriteRule application, DirectoryIndex handling.
 */

#include "ngx_http_htaccess_module.h"
#include <sys/stat.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#if defined(__linux__) && __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#endif


/* defined later in this file - used by %{HTTP:Header} expansion */
static ngx_table_elt_t *hta_find_req_header(ngx_http_request_t *r,
    ngx_str_t *name);
static ngx_int_t hta_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
static void hta_assign_env(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value, unsigned do_unset);

/*
 * Untrusted values must never put a control character into a header or an
 * internal URI: CR/LF/NUL split or truncate it, and RFC 9110 forbids every
 * other control byte but HTAB in a field value (VT, FF, ESC, DEL, ...).
 */
static ngx_inline ngx_int_t
hta_ctl_byte(u_char c)
{
    return (c < 0x20 && c != '\t') || c == 0x7f;
}

static ngx_int_t
hta_value_has_crlf(ngx_str_t *s)
{
    size_t i;
    for (i = 0; i < s->len; i++) {
        if (hta_ctl_byte(s->data[i])) {
            return 1;
        }
    }
    return 0;
}

static void
hta_value_sanitize(ngx_str_t *s)
{
    size_t i;
    for (i = 0; i < s->len; i++) {
        if (hta_ctl_byte(s->data[i])) {
            s->data[i] = ' ';
        }
    }
}

static ngx_int_t
hta_value_contains(ngx_str_t *hay, ngx_str_t *needle)
{
    size_t i;

    if (needle->len == 0) return 1;
    if (hay->len < needle->len) return 0;

    for (i = 0; i + needle->len <= hay->len; i++) {
        if (ngx_memcmp(hay->data + i, needle->data, needle->len) == 0) {
            return 1;
        }
    }
    return 0;
}

ngx_int_t
hta_path_inside_root(ngx_http_request_t *r, ngx_str_t *path)
{
    ngx_http_core_loc_conf_t *clcf;
    char                      resolved[PATH_MAX];
    char                      root[PATH_MAX];
    u_char                    full[HTA_MAX_PATH];
    size_t                    rlen, n;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL || clcf->root.len == 0 || path->len == 0
        || path->len + clcf->root.len + 2 >= sizeof(full))
    {
        return 0;
    }

    {
        ngx_str_t rr;
        if (hta_root_real(r, &rr) != NGX_OK || rr.len >= sizeof(root)) {
            return 0;
        }
        ngx_memcpy(root, rr.data, rr.len + 1);
        rlen = rr.len;
    }

    /*
     * Keep file tests inside the document root.  Without this, a customer
     * can use `RewriteCond /%1 -f` as an existence oracle for arbitrary
     * paths the nginx worker can traverse.
     */
    if (path->data[0] == '/') {
        ngx_memcpy(full, path->data, path->len);
        full[path->len] = '\0';
    } else {
        (void) ngx_snprintf(full, sizeof(full), "%s/%V", root, path);
    }

    if (realpath((char *) full, resolved) == NULL) {
        return 0;
    }

    n = ngx_strlen(resolved);
    if (rlen == 1 && root[0] == '/') {
        return 1;
    }
    if (n < rlen || ngx_memcmp(resolved, root, rlen) != 0) {
        return 0;
    }
    return (n == rlen || resolved[rlen] == '/');
}

/*
 * stat() for RewriteCond file tests, confined to the document root and
 * without a check-then-use race: openat2(RESOLVE_BENEATH) from the root
 * resolves the whole path in one step and refuses to leave the root (Linux
 * 5.6+), so a directory swapped for a symlink cannot reach another tenant.
 * The root is resolved and opened once per request.  On kernels without
 * openat2 the realpath() check of hta_path_inside_root() is used.
 * Returns 0 when the path exists inside the root, -1 otherwise.
 */
static void
hta_close_fd(void *data)
{
    (void) close(*(int *) data);
}

#if defined(SYS_openat2) && defined(RESOLVE_BENEATH)
static ngx_uint_t hta_no_openat2;

static ngx_int_t
hta_root_fd(ngx_http_request_t *r, ngx_str_t *rr, int *fd)
{
    hta_req_ctx_t       *ctx;
    ngx_pool_cleanup_t  *cln;
    int                  f;

    if (hta_root_real(r, rr) != NGX_OK) return NGX_ERROR;
    ctx = hta_req_ctx(r);
    if (ctx == NULL) return NGX_ERROR;

    if (!ctx->root_fd_set) {
        cln = ngx_pool_cleanup_add(r->pool, sizeof(int));
        if (cln == NULL) return NGX_ERROR;
        f = open((char *) rr->data, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (f == -1) return NGX_ERROR;
        *(int *) cln->data = f;
        cln->handler = hta_close_fd;
        ctx->root_fd = f;
        ctx->root_fd_set = 1;
    }

    *fd = ctx->root_fd;
    return NGX_OK;
}
#endif

static ngx_int_t
hta_confined_stat(ngx_http_request_t *r, ngx_str_t *path, struct stat *st,
    ngx_uint_t nofollow)
{
#if defined(SYS_openat2) && defined(RESOLVE_BENEATH)
    ngx_http_core_loc_conf_t *clcf;
    ngx_str_t                 rr;
    u_char                    rel[HTA_MAX_PATH];
    const u_char             *p;
    size_t                    len, clen;
    int                       rootfd, fd;
    struct open_how           how;

    if (hta_no_openat2) goto plain;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL || clcf->root.len == 0
        || hta_root_fd(r, &rr, &rootfd) != NGX_OK)
    {
        return -1;
    }

    p = path->data;
    len = path->len;
    if (len > 0 && p[0] == '/') {
        /* absolute: must start with the real or the configured root */
        clen = clcf->root.len;
        while (clen > 1 && clcf->root.data[clen - 1] == '/') clen--;
        if (len >= rr.len && ngx_memcmp(p, rr.data, rr.len) == 0
            && (len == rr.len || p[rr.len] == '/' || rr.len == 1))
        {
            p += rr.len; len -= rr.len;
        } else if (len >= clen && ngx_memcmp(p, clcf->root.data, clen) == 0
                   && (len == clen || p[clen] == '/'))
        {
            p += clen; len -= clen;
        } else {
            return -1;
        }
    }
    while (len > 0 && *p == '/') { p++; len--; }
    if (len >= sizeof(rel)) return -1;
    if (len == 0) {
        rel[0] = '.'; rel[1] = '\0';
    } else {
        ngx_memcpy(rel, p, len);
        rel[len] = '\0';
    }

    ngx_memzero(&how, sizeof(how));
    how.flags = O_PATH | O_CLOEXEC | (nofollow ? O_NOFOLLOW : 0);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    fd = (int) syscall(SYS_openat2, rootfd, (char *) rel, &how, sizeof(how));
    if (fd == -1) {
        if (errno == ENOSYS) {
            hta_no_openat2 = 1;
            goto plain;
        }
        return -1;
    }
    if (fstat(fd, st) == -1) {
        (void) close(fd);
        return -1;
    }
    (void) close(fd);
    return 0;

plain:
#endif
    if (!hta_path_inside_root(r, path)) return -1;
    return nofollow ? lstat((char *) path->data, st)
                    : stat((char *) path->data, st);
}

static ngx_int_t
hta_uri_has_dotdot(ngx_str_t *s)
{
    u_char *p = s->data, *end = s->data + s->len;

    while (p < end && *p != '?') {
        if (p + 1 < end && p[0] == '.' && p[1] == '.'
            && (p == s->data || p[-1] == '/')
            && (p + 2 == end || p[2] == '/' || p[2] == '?'))
        {
            return 1;
        }
        p++;
    }
    return 0;
}


/*
 * Growing output buffer for expansions.  A value that did not fit used to be
 * dropped silently, so "RewriteCond %{QUERY_STRING} union.*select" saw an
 * empty string for any query string over 4 KB and the deny rule was skipped.
 * Now the buffer grows (in r->pool) up to HTA_MAX_EXPAND, and past that the
 * expansion fails, which fails the request closed.
 */
#define HTA_MAX_EXPAND  (1024 * 1024)

typedef struct {
    ngx_pool_t  *pool;
    u_char      *data;
    size_t       len;
    size_t       cap;
} hta_buf_t;

static ngx_int_t
hta_buf_init(hta_buf_t *b, ngx_pool_t *pool, size_t hint)
{
    b->pool = pool;
    b->len = 0;
    b->cap = hint + 64;
    if (hta_work_alloc(b->cap) != NGX_OK) return NGX_ERROR;
    b->data = ngx_pnalloc(pool, b->cap);
    return b->data ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
hta_buf_put(hta_buf_t *b, const u_char *s, size_t n)
{
    u_char *nd;
    size_t  ncap;

    if (n > HTA_MAX_EXPAND || b->len + n + 1 > HTA_MAX_EXPAND) {
        return NGX_ERROR;
    }
    if (b->len + n + 1 > b->cap) {
        ncap = b->cap * 2;
        if (ncap < b->len + n + 1) ncap = b->len + n + 1;
        if (ncap > HTA_MAX_EXPAND) ncap = HTA_MAX_EXPAND;
        if (hta_work_alloc(ncap) != NGX_OK) return NGX_ERROR;
        nd = ngx_pnalloc(b->pool, ncap);
        if (nd == NULL) return NGX_ERROR;
        ngx_memcpy(nd, b->data, b->len);
        b->data = nd;
        b->cap = ncap;
    }
    ngx_memcpy(b->data + b->len, s, n);
    b->len += n;
    return NGX_OK;
}

static void
hta_buf_done(hta_buf_t *b, ngx_str_t *dst)
{
    b->data[b->len] = '\0';
    dst->data = b->data;
    dst->len = b->len;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Variable expansion - %{VAR_NAME}
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_expand_vars(ngx_http_request_t *r, ngx_str_t *src, ngx_str_t *dst)
{
    u_char    *p = src->data, *end = src->data + src->len;
    hta_buf_t  out;

    if (hta_buf_init(&out, r->pool, src->len) != NGX_OK) return NGX_ERROR;

    while (p < end) {
        if (*p == '%' && p + 1 < end && *(p+1) == '{') {
            u_char    *vs;
            ngx_uint_t vlen;
            ngx_str_t  val = ngx_null_string;

            p += 2;
            vs = p;
            while (p < end && *p != '}') p++;
            if (p >= end) break;

            vlen = p - vs;
            p++;  /* skip } */

            if (vlen > 5 && ngx_strncasecmp(vs, (u_char *)"HTTP:", 5) == 0) {
                /* %{HTTP:Header-Name} - arbitrary request header */
                ngx_str_t        hname;
                ngx_table_elt_t *he;
                hname.data = vs + 5;
                hname.len  = vlen - 5;
                he = hta_find_req_header(r, &hname);
                if (he) val = he->value;
            } else if (vlen > 4 && ngx_strncasecmp(vs, (u_char *)"ENV:", 4) == 0) {
                /* %{ENV:name} - nginx variable set via SetEnv/SetEnvIf/[E=] */
                ngx_str_t lname;
                lname.len  = vlen - 4;
                lname.data = ngx_pnalloc(r->pool, lname.len);
                if (lname.data) {
                    ngx_uint_t                 k, hash;
                    ngx_http_variable_value_t *vv;
                    for (k = 0; k < lname.len; k++)
                        lname.data[k] = ngx_tolower(vs[4 + k]);
                    hash = ngx_hash_key(lname.data, lname.len);
                    vv = ngx_http_get_variable(r, &lname, hash);
                    if (vv && !vv->not_found && vv->len > 0) {
                        val.data = vv->data; val.len = vv->len;
                    }
                }
            } else if (vlen >= 4 && ngx_strncasecmp(vs, (u_char *)"TIME", 4) == 0) {
                /* %{TIME}, %{TIME_YEAR}, %{TIME_MON}, ... (local server time) */
                struct tm  tmv;
                u_char    *b = ngx_pnalloc(r->pool, 16);
                ngx_libc_localtime(ngx_time(), &tmv);
                if (b) {
                    val.data = b;
                    if (vlen == 4)
                        val.len = ngx_sprintf(b, "%04d%02d%02d%02d%02d%02d",
                            tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                            tmv.tm_hour, tmv.tm_min, tmv.tm_sec) - b;
                    else if (vlen == 9 && ngx_strncasecmp(vs+5,(u_char*)"YEAR",4)==0)
                        val.len = ngx_sprintf(b, "%04d", tmv.tm_year+1900) - b;
                    else if (vlen == 8 && ngx_strncasecmp(vs+5,(u_char*)"MON",3)==0)
                        val.len = ngx_sprintf(b, "%02d", tmv.tm_mon+1) - b;
                    else if (vlen == 8 && ngx_strncasecmp(vs+5,(u_char*)"DAY",3)==0)
                        val.len = ngx_sprintf(b, "%02d", tmv.tm_mday) - b;
                    else if (vlen == 9 && ngx_strncasecmp(vs+5,(u_char*)"HOUR",4)==0)
                        val.len = ngx_sprintf(b, "%02d", tmv.tm_hour) - b;
                    else if (vlen == 8 && ngx_strncasecmp(vs+5,(u_char*)"MIN",3)==0)
                        val.len = ngx_sprintf(b, "%02d", tmv.tm_min) - b;
                    else if (vlen == 8 && ngx_strncasecmp(vs+5,(u_char*)"SEC",3)==0)
                        val.len = ngx_sprintf(b, "%02d", tmv.tm_sec) - b;
                    else if (vlen == 9 && ngx_strncasecmp(vs+5,(u_char*)"WDAY",4)==0)
                        val.len = ngx_sprintf(b, "%d", tmv.tm_wday) - b;
                    else
                        val.data = NULL;  /* unknown TIME_* -> empty */
                }
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"REQUEST_URI", 11) == 0) {
                /*
                 * Apache REQUEST_URI is the original request URI, including
                 * the query string; r->uri is the current, possibly
                 * rewritten path and must not be used for security gates.
                 */
                if (!r->internal && r->unparsed_uri.len > 0) {
                    val = r->unparsed_uri;
                } else {
                    /* After an internal redirect the original URI would make
                     * a REQUEST_URI-gated catch-all re-fire forever. */
                    val = r->uri;
                }
            } else if (vlen == 16 && ngx_strncasecmp(vs, (u_char *)"REQUEST_FILENAME", 16) == 0) {
                /* Filesystem path of the request. map_uri_to_path is alias-aware
                 * (matches the alias-fixed .htaccess collection); the old
                 * root+uri concat double-counted the location prefix under an
                 * `alias`, so the "-f/-d -> index.php" guard always misfired.
                 * Security: reject ".." first (map_uri_to_path does not). */
                if (ngx_strnstr(r->uri.data, "..", r->uri.len) == NULL) {
                    ngx_str_t path;
                    size_t    rl;
                    u_char   *last = ngx_http_map_uri_to_path(r, &path, &rl, 0);
                    if (last != NULL) {
                        val.data = path.data;
                        val.len  = last - path.data;
                    }
                }
            } else if (vlen == 15 && ngx_strncasecmp(vs, (u_char *)"SCRIPT_FILENAME", 15) == 0) {
                /* same on-disk path as REQUEST_FILENAME in this context */
                if (ngx_strnstr(r->uri.data, "..", r->uri.len) == NULL) {
                    ngx_str_t path;
                    size_t    rl;
                    u_char   *last = ngx_http_map_uri_to_path(r, &path, &rl, 0);
                    if (last != NULL) {
                        val.data = path.data;
                        val.len  = last - path.data;
                    }
                }
            } else if (vlen == 12 && ngx_strncasecmp(vs, (u_char *)"QUERY_STRING", 12) == 0) {
                val = r->args;
            } else if (vlen == 9 && ngx_strncasecmp(vs, (u_char *)"HTTP_HOST", 9) == 0) {
                if (r->headers_in.host) val = r->headers_in.host->value;
            } else if (vlen == 15 && ngx_strncasecmp(vs, (u_char *)"HTTP_USER_AGENT", 15) == 0) {
                if (r->headers_in.user_agent) val = r->headers_in.user_agent->value;
            } else if (vlen == 12 && ngx_strncasecmp(vs, (u_char *)"HTTP_REFERER", 12) == 0) {
                if (r->headers_in.referer) val = r->headers_in.referer->value;
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"HTTP_COOKIE", 11) == 0) {
                /* HTTP_COOKIE - use nginx variable fallback */
                goto nginx_var_fallback;
            } else if (vlen == 20 && ngx_strncasecmp(vs, (u_char *)"HTTP_ACCEPT_LANGUAGE", 20) == 0) {
                goto nginx_var_fallback;
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"HTTP_ACCEPT", 11) == 0) {
                goto nginx_var_fallback;
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"REMOTE_ADDR", 11) == 0) {
                val = r->connection->addr_text;
            } else if (vlen == 14 && ngx_strncasecmp(vs, (u_char *)"REQUEST_METHOD", 14) == 0) {
                val = r->method_name;
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"SERVER_NAME", 11) == 0) {
                ngx_http_core_srv_conf_t *cscf;
                cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
                val = cscf->server_name;
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"SERVER_PORT", 11) == 0) {
                ngx_uint_t port;
                port = ngx_inet_get_port(r->connection->local_sockaddr);
                val.data = ngx_pnalloc(r->pool, 8);
                if (val.data) {
                    val.len = ngx_snprintf(val.data, 8, "%ui", port) - val.data;
                }
            } else if (vlen == 5 && ngx_strncasecmp(vs, (u_char *)"HTTPS", 5) == 0) {
                ngx_http_hta_loc_conf_t *hlcf;
                unsigned                 is_https = 0;

#if (NGX_HTTP_SSL)
                if (r->connection->ssl) is_https = 1;
#endif
                hlcf = ngx_http_get_module_loc_conf(r,
                                                   ngx_http_htaccess_module);
                if (!is_https && hlcf && hlcf->trust_proxy) {
                    ngx_list_part_t *part = &r->headers_in.headers.part;
                    ngx_table_elt_t *hdr = part->elts;
                    ngx_uint_t       hi;
                    for (hi = 0;; hi++) {
                        if (hi >= part->nelts) {
                            if (part->next == NULL) break;
                            part = part->next; hdr = part->elts; hi = 0;
                        }
                        if (hdr[hi].key.len == sizeof("X-Forwarded-Proto") - 1
                            && ngx_strncasecmp(hdr[hi].key.data,
                                (u_char *) "X-Forwarded-Proto",
                                sizeof("X-Forwarded-Proto") - 1) == 0
                            && hdr[hi].value.len == 5
                            && ngx_strncasecmp(hdr[hi].value.data,
                                (u_char *) "https", 5) == 0)
                        {
                            is_https = 1;
                            break;
                        }
                    }
                }
                if (is_https) {
                    val.data = (u_char *) "on";
                    val.len = 2;
                } else {
                    ngx_str_set(&val, "off");
                }
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"THE_REQUEST", 11) == 0) {
                val = r->request_line;
            } else if (vlen == 13 && ngx_strncasecmp(vs, (u_char *)"DOCUMENT_ROOT", 13) == 0) {
                ngx_http_core_loc_conf_t *clcf;
                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                val = clcf->root;
            } else if (vlen == 15 && ngx_strncasecmp(vs, (u_char *)"SERVER_PROTOCOL", 15) == 0) {
                val = r->http_protocol;
            } else if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"REMOTE_HOST", 11) == 0) {
                val = r->connection->addr_text;
            } else if (vlen == 14 && ngx_strncasecmp(vs, (u_char *)"REQUEST_SCHEME", 14) == 0) {
                /* nginx has no $request_scheme; derive it directly. */
#if (NGX_HTTP_SSL)
                if (r->connection->ssl) { ngx_str_set(&val, "https"); }
                else                    { ngx_str_set(&val, "http"); }
#else
                ngx_str_set(&val, "http");
#endif
            } else {
nginx_var_fallback:
                /* fallback: nginx variable lookup */
                {
                ngx_str_t lname;
                lname.data = ngx_pnalloc(r->pool, vlen);
                if (lname.data) {
                    ngx_uint_t                 k;
                    ngx_uint_t                 hash;
                    ngx_http_variable_value_t *vv;
                    for (k = 0; k < vlen; k++)
                        lname.data[k] = ngx_tolower(vs[k]);
                    lname.len = vlen;
                    hash = ngx_hash_key(lname.data, lname.len);
                    vv = ngx_http_get_variable(r, &lname, hash);
                    if (vv && !vv->not_found && vv->len > 0) {
                        val.data = vv->data; val.len = vv->len;
                    }
                }
                }
            }

            if (val.len > 0 && hta_buf_put(&out, val.data, val.len) != NGX_OK) {
                return NGX_ERROR;
            }
        } else {
            if (hta_buf_put(&out, p, 1) != NGX_OK) return NGX_ERROR;
            p++;
        }
    }

    hta_buf_done(&out, dst);
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Backreference context for a rule being applied:
 *   $0-$9  -> capture groups of the RewriteRule pattern (rule_subject)
 *   %0-%9  -> capture groups of the last matching RewriteCond (cond_subject)
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    ngx_str_t   rule_subject;
    int        *rule_caps;
    ngx_uint_t  rule_ncaps;
    ngx_str_t   cond_subject;
    int        *cond_caps;
    ngx_uint_t  cond_ncaps;
    unsigned    have_rule:1;
    unsigned    have_cond:1;
} hta_backref_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Full expansion: %{VAR}, $N (rule backref), %N (cond backref)
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_expand_full(ngx_http_request_t *r, ngx_str_t *src, ngx_str_t *dst,
    hta_backref_t *br)
{
    u_char    *p = src->data, *end = src->data + src->len;
    hta_buf_t  out;

    if (hta_buf_init(&out, r->pool, src->len) != NGX_OK) return NGX_ERROR;

    while (p < end) {
        if (*p == '$' && p + 1 < end && *(p+1) >= '0' && *(p+1) <= '9'
            && br && br->have_rule)
        {
            ngx_uint_t n = *(p+1) - '0';
            p += 2;
            if (n < br->rule_ncaps / 2) {
                int s = br->rule_caps[n*2], e = br->rule_caps[n*2+1];
                if (s >= 0 && e >= s) {
                    if (hta_buf_put(&out, br->rule_subject.data + s,
                                    (size_t) (e - s)) != NGX_OK)
                    {
                        return NGX_ERROR;
                    }
                }
            }
        } else if (*p == '%' && p + 1 < end && *(p+1) >= '0' && *(p+1) <= '9'
                   && br && br->have_cond)
        {
            ngx_uint_t n = *(p+1) - '0';
            p += 2;
            if (n < br->cond_ncaps / 2) {
                int s = br->cond_caps[n*2], e = br->cond_caps[n*2+1];
                if (s >= 0 && e >= s) {
                    if (hta_buf_put(&out, br->cond_subject.data + s,
                                    (size_t) (e - s)) != NGX_OK)
                    {
                        return NGX_ERROR;
                    }
                }
            }
        } else if (*p == '%' && p + 1 < end && *(p+1) == '{') {
            ngx_str_t vref, exp;
            u_char *vstart = p;
            while (p < end && *p != '}') p++;
            if (p < end) p++;
            vref.data = vstart; vref.len = p - vstart;
            if (hta_expand_vars(r, &vref, &exp) != NGX_OK
                || (exp.len > 0 && hta_buf_put(&out, exp.data, exp.len) != NGX_OK))
            {
                return NGX_ERROR;
            }
        } else {
            if (hta_buf_put(&out, p, 1) != NGX_OK) return NGX_ERROR;
            p++;
        }
    }

    hta_buf_done(&out, dst);
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Substitution with backreferences ($1..$9, %1..%9) and variables (%{VAR})
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_substitute(ngx_http_request_t *r, hta_rule_t *rule, ngx_str_t *uri,
    hta_backref_t *br)
{
    if (ngx_strcmp(rule->substitution.data, "-") == 0)
        return NGX_DECLINED;

    return hta_expand_full(r, &rule->substitution, uri, br);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Condition evaluator - handles AND/OR groups correctly
 *
 * Apache logic: conditions are evaluated as groups connected by AND.
 * Within a group, conditions connected by [OR] are OR'd together.
 * The final result is: group1 AND group2 AND ...
 * where each group is: cond1 OR cond2 OR ... OR condN (last without [OR])
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_eval_conds(ngx_http_request_t *r, hta_rule_t *rule, hta_backref_t *br,
    int *cond_caps, ngx_str_t *cond_subject)
{
    ngx_uint_t i;
    ngx_int_t  final_result = 1;
    ngx_int_t  group_result = 0;
    unsigned   in_or_group = 0;
    uint64_t   t0;

    if (rule->nconds == 0) return NGX_OK;

    for (i = 0; i < rule->nconds; i++) {
        hta_cond_t *c;
        ngx_int_t   match;
        ngx_str_t   expanded;
        ngx_str_t   rhs;

        c = &rule->conds[i];
        match = 0;
        /* regex conditions are timed inside hta_regex_exec(); the rest
         * (expansion, comparisons, file tests) is timed here */
        t0 = (c->test_type == HTA_TEST_REGEX) ? 0 : hta_work_start();
        /* expand %{VAR} and, since the rule pattern was matched first, $N
         * backreferences from the rule (e.g. CodeIgniter "RewriteCond $1 ...") */
        if (hta_expand_full(r, &c->test_string, &expanded, br) != NGX_OK)
            return NGX_ERROR;

        /* comparison operators: the RHS operand may itself reference
         * %{VAR}/$N/%N (e.g. "RewriteCond %{HTTP_HOST} =%{SERVER_NAME}") */
        rhs = c->cond_pattern;
        if (c->test_type >= HTA_TEST_STR_EQ
            && hta_expand_full(r, &c->cond_pattern, &rhs, br) != NGX_OK)
            rhs = c->cond_pattern;

        switch (c->test_type) {
        case HTA_TEST_REGEX:
            if (c->regex) {
                int       lcaps[HTA_MAX_CAPTURES];
                ngx_int_t nrc = hta_regex_exec(c->regex, &expanded, lcaps,
                                               HTA_MAX_CAPTURES);
                if (nrc == HTA_REGEX_ERROR) {
                    return NGX_ERROR;
                }
                match = (nrc >= 0);
                if (match && !(c->flags & HTA_CF_NEGATE)) {
                    /* remember captures for %1-%9 in the substitution; the
                     * last positively-matched RewriteCond wins (Apache) */
                    ngx_memcpy(cond_caps, lcaps, sizeof(int) * HTA_MAX_CAPTURES);
                    *cond_subject     = expanded;
                    br->cond_caps     = cond_caps;
                    br->cond_subject  = *cond_subject;
                    br->cond_ncaps    = (nrc > 0) ? (ngx_uint_t) nrc * 2 : 2;
                    br->have_cond     = 1;
                }
            }
            break;
        case HTA_TEST_FILE: {
            struct stat st;
            /* confined to the document root, see hta_confined_stat() */
            match = (hta_confined_stat(r, &expanded, &st, 0) == 0
                     && S_ISREG(st.st_mode));
            break;
        }
        case HTA_TEST_DIR: {
            struct stat st;
            match = (hta_confined_stat(r, &expanded, &st, 0) == 0
                     && S_ISDIR(st.st_mode));
            break;
        }
        case HTA_TEST_LINK: {
            struct stat st;
            match = (hta_confined_stat(r, &expanded, &st, 1) == 0
                     && S_ISLNK(st.st_mode));
            break;
        }
        case HTA_TEST_EXISTS: {
            struct stat st;
            match = (hta_confined_stat(r, &expanded, &st, 0) == 0);
            break;
        }
        case HTA_TEST_SIZE: {
            struct stat st;
            match = (hta_confined_stat(r, &expanded, &st, 0) == 0
                     && st.st_size > 0);
            break;
        }
        case HTA_TEST_STR_EQ:
            match = (ngx_strcmp(expanded.data, rhs.data) == 0);
            break;
        case HTA_TEST_STR_LT:
            match = (ngx_strcmp(expanded.data, rhs.data) < 0);
            break;
        case HTA_TEST_STR_GT:
            match = (ngx_strcmp(expanded.data, rhs.data) > 0);
            break;
        case HTA_TEST_STR_LE:
            match = (ngx_strcmp(expanded.data, rhs.data) <= 0);
            break;
        case HTA_TEST_STR_GE:
            match = (ngx_strcmp(expanded.data, rhs.data) >= 0);
            break;
        case HTA_TEST_INT_EQ:
        case HTA_TEST_INT_NE:
        case HTA_TEST_INT_LT:
        case HTA_TEST_INT_LE:
        case HTA_TEST_INT_GT:
        case HTA_TEST_INT_GE: {
            ngx_int_t a = ngx_atoi(expanded.data, expanded.len);
            ngx_int_t b = ngx_atoi(rhs.data, rhs.len);
            if (a == NGX_ERROR) a = 0;
            if (b == NGX_ERROR) b = 0;
            switch (c->test_type) {
            case HTA_TEST_INT_EQ: match = (a == b); break;
            case HTA_TEST_INT_NE: match = (a != b); break;
            case HTA_TEST_INT_LT: match = (a <  b); break;
            case HTA_TEST_INT_LE: match = (a <= b); break;
            case HTA_TEST_INT_GT: match = (a >  b); break;
            default:              match = (a >= b); break;  /* -ge */
            }
            break;
        }
        }

        if (hta_work_stop(t0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (c->flags & HTA_CF_NEGATE) match = !match;

        /* OR/AND group logic */
        if (c->flags & HTA_CF_OR) {
            /* This condition has [OR] flag - accumulate into OR group */
            if (!in_or_group) {
                group_result = match;
                in_or_group = 1;
            } else {
                group_result = group_result || match;
            }
        } else {
            /* No [OR] flag - this terminates the current OR group (if any) */
            if (in_or_group) {
                /* Final member of OR group */
                group_result = group_result || match;
                in_or_group = 0;
                final_result = final_result && group_result;
            } else {
                /* Standalone AND condition */
                final_result = final_result && match;
            }
        }
    }

    /* If we ended in an OR group, close it */
    if (in_or_group) {
        final_result = final_result && group_result;
    }

    return final_result ? NGX_OK : NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * DirectoryIndex - check for index files when URI ends with /
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_apply_dirindex(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_http_core_loc_conf_t *clcf;
    u_char path[HTA_MAX_PATH];
    ngx_uint_t i;
    ngx_file_info_t fi;

    if (h->nindex == 0) return NGX_DECLINED;
    if (r->uri.len == 0 || r->uri.data[r->uri.len - 1] != '/')
        return NGX_DECLINED;
    if (hta_uri_has_dotdot(&r->uri)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    for (i = 0; i < h->nindex; i++) {
        ngx_int_t plen;

        if (hta_uri_has_dotdot(&h->index_files[i])
            || (h->index_files[i].len > 0
                && h->index_files[i].data[0] == '/'))
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        plen = ngx_snprintf(path, sizeof(path), "%V%V%V",
                            &clcf->root, &r->uri,
                            &h->index_files[i]) - path;
        if (plen < 0 || plen >= (ngx_int_t) sizeof(path) - 1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        path[plen] = '\0';

        if (ngx_file_info(path, &fi) == 0 && ngx_is_file(&fi)) {
            ngx_str_t nuri;
            nuri.len = r->uri.len + h->index_files[i].len;
            nuri.data = ngx_pnalloc(r->pool, nuri.len + 1);
            if (nuri.data == NULL) return NGX_ERROR;
            ngx_memcpy(nuri.data, r->uri.data, r->uri.len);
            ngx_memcpy(nuri.data + r->uri.len, h->index_files[i].data,
                       h->index_files[i].len);
            nuri.data[nuri.len] = '\0';
            r->uri = nuri;
            r->valid_location = 0;
            r->valid_unparsed_uri = 0;
            r->uri_changed = 1;
            return NGX_DECLINED;
        }
    }
    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * FallbackResource - serve a front controller when the request maps to no
 * existing file (mod_dir). $request_uri stays the original, so the app still
 * sees the routed path (same as nginx `try_files $uri /index.php`).
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_apply_fallback(ngx_http_request_t *r, ngx_str_t *fallback)
{
    ngx_str_t       path, target;
    size_t          rl;
    u_char         *last;
    ngx_file_info_t fi;

    if (fallback->len == 0) return NGX_DECLINED;

    if (hta_pstrdup(r, &target, fallback) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (hta_value_has_crlf(&target) || hta_uri_has_dotdot(&target)
        || target.len == 0 || target.data[0] != '/')
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* avoid an internal-redirect loop onto the fallback itself */
    if (r->uri.len == target.len
        && ngx_strncmp(r->uri.data, target.data, target.len) == 0)
        return NGX_DECLINED;

    /* only fall back when the request maps to no existing file or directory */
    if (ngx_strnstr(r->uri.data, "..", r->uri.len) != NULL) return NGX_DECLINED;
    last = ngx_http_map_uri_to_path(r, &path, &rl, 1);
    if (last != NULL) {
        *last = '\0';
        if (ngx_file_info(path.data, &fi) == 0
            && (ngx_is_file(&fi) || ngx_is_dir(&fi)))
            return NGX_DECLINED;
    }

    return hta_internal_redirect(r, &target, &r->args);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Rewrite rules engine
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_apply_rules(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;
    ngx_str_t  uri;
    int        caps[HTA_MAX_CAPTURES];
    ngx_int_t  rc;
    ngx_uint_t skip = 0;
    unsigned   changed = 0;

    if (!h->rewrite_on || h->nrules == 0) return NGX_DECLINED;

    /*
     * Apache per-directory context: the match subject is the request path
     * relative to the directory containing this .htaccess, with the leading
     * slash removed.  RewriteBase only affects relative substitutions, not
     * the match subject.  The old code stripped only "/" (or RewriteBase),
     * so ^secret$ in /private/.htaccess was matched against "private/secret"
     * and never fired.
     */
    uri = r->uri;
    if (uri.len > 0 && uri.data[0] == '/') {
        ngx_http_core_loc_conf_t *clcf;
        size_t                    skip = 1;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        if (clcf != NULL && clcf->alias != 0
            && clcf->alias != NGX_MAX_SIZE_T_VALUE
            && clcf->alias <= uri.len)
        {
            skip = clcf->alias;
        }

        if (h->dir_rel.len > 0
            && uri.len >= skip + h->dir_rel.len
            && ngx_strncmp(uri.data + skip, h->dir_rel.data,
                           h->dir_rel.len) == 0)
        {
            uri.data += skip + h->dir_rel.len;
            uri.len  -= skip + h->dir_rel.len;
        } else {
            if (uri.len >= skip) {
                uri.data += skip;
                uri.len  -= skip;
            }
        }
    }

    for (i = 0; i < h->nrules; i++) {
        hta_rule_t   *rule;
        ngx_str_t     nuri;
        ngx_str_t     nargs;
        u_char       *q;
        hta_backref_t br;
        int           cond_caps[HTA_MAX_CAPTURES];
        ngx_str_t     cond_subject = ngx_null_string;

        rule = &h->rules[i];

        if (skip > 0) { skip--; continue; }

        /* Apache evaluates the RewriteRule pattern FIRST; the RewriteConds run
         * only if it matches, and can back-reference its captures via $N. */
        rc = hta_regex_exec(rule->regex, &uri, caps, HTA_MAX_CAPTURES);
        if (rc == HTA_REGEX_ERROR) {
            return NGX_ERROR;
        }

        if (rule->flags & HTA_F_NOT) {
            if (rc >= 0) {
                /* pattern matched, so the negated rule does not */
                if (rule->flags & HTA_F_CHAIN) {
                    ngx_uint_t j = i + 1;
                    while (j < h->nrules
                           && h->rules[j-1].flags & HTA_F_CHAIN) j++;
                    i = j - 1;
                }
                continue;
            }
            rc = NGX_REGEX_NO_MATCHED;
        } else if (rc == NGX_REGEX_NO_MATCHED) {
            if (rule->flags & HTA_F_CHAIN) {
                ngx_uint_t j = i + 1;
                while (j < h->nrules && h->rules[j-1].flags & HTA_F_CHAIN) j++;
                i = j - 1;
            }
            continue;
        } else if (rc < 0) {
            return NGX_ERROR;
        }

        ngx_memzero(&br, sizeof(br));
        br.rule_subject = uri;
        if (!(rule->flags & HTA_F_NOT)) {
            br.rule_caps  = caps;
            br.rule_ncaps = (rc > 0) ? (ngx_uint_t) rc * 2 : 2;
            br.have_rule  = 1;
        }

        /* now the conditions (they see $N from the rule and capture %N) */
        {
            ngx_int_t crc = hta_eval_conds(r, rule, &br, cond_caps,
                                           &cond_subject);
            if (crc == NGX_DECLINED) {
                if (rule->flags & HTA_F_CHAIN) {
                    ngx_uint_t j = i + 1;
                    while (j < h->nrules
                           && h->rules[j-1].flags & HTA_F_CHAIN) j++;
                    i = j - 1;
                }
                continue;
            }
            if (crc == NGX_ERROR) return NGX_ERROR;
        }

        /* === matched === */

        /* apply [E=key:val] flag - set an nginx variable, under the same
         * rules as SetEnv (htaccess_env_allow, changeable variables only):
         * writing $remote_addr or a limit key from .htaccess forged logs,
         * PHP's REMOTE_ADDR and other tenants' limits */
        if (rule->flags & HTA_F_ENV && rule->env_key.len > 0) {
            /* the E= value may reference %{VAR}/$N/%N, e.g.
             * [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}] */
            ngx_str_t ev;
            if (hta_expand_full(r, &rule->env_val, &ev, &br) != NGX_OK
                && hta_pstrdup(r, &ev, &rule->env_val) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            hta_value_sanitize(&ev);
            hta_assign_env(r, &rule->env_key, &ev, 0);
            {
                hta_req_ctx_t *ctx = hta_req_ctx(r);
                ngx_str_t     *kv;
                if (ctx != NULL && ctx->env_late == NULL) {
                    ctx->env_late = ngx_array_create(r->pool, 4,
                                                     2 * sizeof(ngx_str_t));
                }
                if (ctx != NULL && ctx->env_late != NULL
                    && ctx->env_late->nelts < HTA_MAX_RULES)
                {
                    /* copies in r->pool: the cached rule may be evicted
                     * before the preaccess phase runs */
                    kv = ngx_array_push(ctx->env_late);
                    if (kv != NULL
                        && (hta_pstrdup(r, &kv[0], &rule->env_key) != NGX_OK
                            || hta_pstrdup(r, &kv[1], &ev) != NGX_OK))
                    {
                        ctx->env_late->nelts--;
                    }
                }
            }
        }

        if (rule->flags & HTA_F_FORBIDDEN) return NGX_HTTP_FORBIDDEN;
        if (rule->flags & HTA_F_GONE)      return 410;

        /* [R=4xx/5xx]: respond with the status directly (before substitution),
         * so the "- [R=404]" / "x - [R=403]" hide-file idiom actually returns
         * the error instead of silently no-op'ing when the substitution is "-"
         * and serving the "hidden" resource. */
        if ((rule->flags & HTA_F_REDIRECT)
            && rule->redirect_code >= 400 && rule->redirect_code <= 599)
        {
            return rule->redirect_code;
        }

        /* apply substitution */
        nuri = uri;
        rc = hta_substitute(r, rule, &nuri, &br);
        if (rc == NGX_DECLINED) {
            if (rule->flags & (HTA_F_LAST | HTA_F_END)) break;
            if (rule->flags & HTA_F_SKIP) skip = rule->skip_count;
            continue;
        }
        if (rc == NGX_ERROR) return NGX_ERROR;

        if (rule->flags & HTA_F_SKIP) skip = rule->skip_count;

        /*
         * Never let a customer-supplied substitution write CR/LF into a
         * Location header, or escape the document root with "..".
         */
        if (hta_value_has_crlf(&nuri) || hta_uri_has_dotdot(&nuri)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "htaccess: unsafe rewrite target, failing closed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* external redirect? */
        if ((rule->flags & HTA_F_REDIRECT) ||
            (nuri.len >= 7 &&
             (ngx_strncasecmp(nuri.data, (u_char *)"http://", 7) == 0 ||
              ngx_strncasecmp(nuri.data, (u_char *)"https://", 8) == 0)))
        {
            ngx_int_t        code = rule->redirect_code;
            ngx_table_elt_t *loc;

            if (code < 300 || code > 399) code = 302;

            /* Query string: Apache appends the original ?query to a redirect
             * target that has none (default passthrough); [QSA] also merges it
             * onto a target that already has a query; [QSD] discards it. The
             * old code only handled QSA, so canonical www/HTTPS 301s silently
             * dropped ?args. */
            if (!(rule->flags & HTA_F_QSD) && r->args.len > 0) {
                u_char *has_q = (u_char *) ngx_strchr(nuri.data, '?');
                if (has_q == NULL || (rule->flags & HTA_F_QSA)) {
                    u_char  sep = has_q ? '&' : '?';
                    u_char *quri = ngx_pnalloc(r->pool,
                                               nuri.len + 1 + r->args.len + 1);
                    if (quri) {
                        nuri.len = ngx_sprintf(quri, "%V%c%V",
                                               &nuri, sep, &r->args) - quri;
                        nuri.data = quri;
                    }
                }
            }

            if (hta_value_has_crlf(&nuri)) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            loc = ngx_list_push(&r->headers_out.headers);
            if (loc == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            loc->hash = 1;
            ngx_str_set(&loc->key, "Location");
            loc->value = nuri;
            r->headers_out.status = code;
            r->headers_out.content_length_n = 0;
            return code;
        }

        /* internal: prepend base/slash */
        if (nuri.len > 0 && nuri.data[0] != '/') {
            u_char *pre;
            if (h->rewrite_base.len > 0) {
                ngx_uint_t plen = h->rewrite_base.len + nuri.len;
                pre = ngx_pnalloc(r->pool, plen + 1);
                if (pre) {
                    ngx_memcpy(pre, h->rewrite_base.data,
                               h->rewrite_base.len);
                    ngx_memcpy(pre + h->rewrite_base.len,
                               nuri.data, nuri.len);
                    pre[plen] = '\0';
                    nuri.data = pre; nuri.len = plen;
                }
            } else {
                ngx_uint_t plen = 1 + h->dir_rel.len + nuri.len;
                pre = ngx_pnalloc(r->pool, plen + 1);
                if (pre) {
                    pre[0] = '/';
                    if (h->dir_rel.len > 0) {
                        ngx_memcpy(pre + 1, h->dir_rel.data, h->dir_rel.len);
                    }
                    ngx_memcpy(pre + 1 + h->dir_rel.len, nuri.data, nuri.len);
                    pre[plen] = '\0';
                    nuri.data = pre; nuri.len = plen;
                }
            }
        }

        /* query string handling */
        nargs = r->args;
        q = (u_char *)ngx_strchr(nuri.data, '?');
        if (q) {
            nargs.data = q + 1;
            nargs.len = nuri.len - (q + 1 - nuri.data);
            nuri.len = q - nuri.data;
            *q = '\0';
            if ((rule->flags & HTA_F_QSA) && r->args.len > 0) {
                u_char *ca = ngx_pnalloc(r->pool,
                                         nargs.len + 1 + r->args.len + 1);
                if (ca) {
                    nargs.len = ngx_sprintf(ca, "%V&%V",
                                            &nargs, &r->args) - ca;
                    nargs.data = ca;
                }
            }
        } else if (rule->flags & HTA_F_QSD) {
            nargs.data = NULL; nargs.len = 0;
        }

        if (rule->flags & (HTA_F_LAST | HTA_F_END)) {
            r->uri = nuri;
            r->args = nargs;
            r->valid_location = 0;
            r->valid_unparsed_uri = 0;
            r->uri_changed = 1;
            return NGX_DECLINED;
        }

        /* continue with rewritten URI */
        r->uri = nuri;
        r->args = nargs;
        changed = 1;
        uri = nuri;
        if (uri.len > 0 && uri.data[0] == '/') {
            ngx_http_core_loc_conf_t *clcf2;
            size_t                    skip2 = 1;

            clcf2 = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            if (clcf2 != NULL && clcf2->alias != 0
                && clcf2->alias != NGX_MAX_SIZE_T_VALUE
                && clcf2->alias <= uri.len)
            {
                skip2 = clcf2->alias;
            }

            if (h->dir_rel.len > 0
                && uri.len >= skip2 + h->dir_rel.len
                && ngx_strncmp(uri.data + skip2, h->dir_rel.data,
                               h->dir_rel.len) == 0)
            {
                uri.data += skip2 + h->dir_rel.len;
                uri.len  -= skip2 + h->dir_rel.len;
            } else if (uri.len >= skip2) {
                uri.data += skip2;
                uri.len  -= skip2;
            }
        }
    }

    /* A rule rewrote the URI but none carried [L]/[END]. Apache re-runs the
     * per-directory ruleset on the new URI; the nginx equivalent is to flag the
     * URI changed so the location is matched again. Without this nginx stays in
     * the original location and could serve the rewritten target (e.g. a .php
     * file) through the static handler - a source-disclosure hazard. nginx caps
     * the number of re-walks (then 500), matching Apache's redirect limit. */
    if (changed) {
        r->valid_location = 0;
        r->valid_unparsed_uri = 0;
        r->uri_changed = 1;
    }

    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Redirect / RedirectMatch / RedirectPermanent / RedirectTemp
 *
 * Applies simple URL redirects (prefix match or regex match).
 * Called before RewriteRule processing.
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * ngx_http_internal_redirect() increments r->main->count.  The rewrite/access
 * phase checkers return NGX_OK for NGX_DONE without finalizing the request,
 * so a caller in those phases must drop the extra reference itself.
 */
static ngx_int_t
hta_internal_redirect(ngx_http_request_t *r, ngx_str_t *uri, ngx_str_t *args)
{
    ngx_int_t rc = ngx_http_internal_redirect(r, uri, args);
    ngx_http_finalize_request(r, NGX_DONE);
    return rc;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * ErrorDocument - redirect to custom error page for a given status code
 * Returns the original status if no ErrorDocument is configured
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_errdoc(ngx_http_request_t *r, hta_errdoc_t *errdocs,
    ngx_uint_t nerrdocs, ngx_int_t status)
{
    ngx_uint_t i;

    if (nerrdocs == 0 || status < 400) return status;
    if (r->error_page) return status;  /* already serving an error page */

    /* Deepest .htaccess wins, matching Apache's nearest-scope precedence. */
    for (i = nerrdocs; i > 0; i--) {
        ngx_uint_t idx = i - 1;

        if (errdocs[idx].code == status) {
            if (errdocs[idx].is_url) {
                ngx_table_elt_t *loc;
                ngx_str_t        uri;

                if (hta_pstrdup(r, &uri, &errdocs[idx].response) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if (hta_value_has_crlf(&uri) || hta_uri_has_dotdot(&uri)) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                if (uri.data[0] == '/') {
                    /*
                     * Preserve the original status on the custom error page
                     * (Apache semantics: /errors/404.html is served with 404,
                     * not 200).  r->err_status survives internal_redirect and
                     * is applied by the header filter.
                     */
                    r->err_status = status;
                    r->error_page = 1;
                    return hta_internal_redirect(r, &uri, &r->args);
                }
                /* external URL - 302 redirect */
                loc = ngx_list_push(
                    &r->headers_out.headers);
                if (loc == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                loc->hash = 1;
                ngx_str_set(&loc->key, "Location");
                loc->value = uri;
                r->headers_out.status = 302;
                r->headers_out.content_length_n = 0;
                return 302;
            }
            /* non-URL response - return original status,
             * response text would need content handler */
            return status;
        }
    }
    return status;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * SetEnvIf - evaluate and set environment variables as nginx variables
 * ═══════════════════════════════════════════════════════════════════════ */

/* Set or clear an nginx variable given its case-preserving name.
 * On set, env_value is the new value; on unset, the variable is marked
 * not_found so consumers see it as absent (matching Apache UnsetEnv).
 */
static ngx_int_t
hta_env_allowed(ngx_http_request_t *r, ngx_str_t *lname)
{
    ngx_http_hta_loc_conf_t  *lcf;
    ngx_str_t                *a;
    ngx_uint_t                i;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (lcf == NULL || lcf->env_allow == NULL) {
        return 0;
    }

    a = lcf->env_allow->elts;
    for (i = 0; i < lcf->env_allow->nelts; i++) {
        if (a[i].len > 0 && a[i].data[a[i].len - 1] == '*') {
            if (lname->len >= a[i].len - 1
                && ngx_strncasecmp(lname->data, a[i].data, a[i].len - 1) == 0)
            {
                return 1;
            }
        } else if (a[i].len == lname->len
                   && ngx_strncasecmp(lname->data, a[i].data, a[i].len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static void
hta_assign_env(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value,
    unsigned do_unset)
{
    ngx_str_t                   lname, copy;
    ngx_uint_t                  k, hash;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_variable_t        *var;
    ngx_http_variable_value_t  *vv;

    if (name->len == 0) return;

    lname.len = name->len;
    lname.data = ngx_pnalloc(r->pool, lname.len);
    if (lname.data == NULL) return;
    for (k = 0; k < lname.len; k++)
        lname.data[k] = ngx_tolower(name->data[k]);

    hash = ngx_hash_key(lname.data, lname.len);

    /*
     * The operator lists what .htaccess may write (htaccess_env_allow).  A
     * changeable variable is not enough: "set $acct <uid>; limit_conn ...
     * $acct" in a site's server block would let the customer move their
     * requests into another account's limit, or out of every limit.
     */
    /* INFO, not WARN: stock CMS files (WordPress, Joomla, Laravel) set
     * [E=HTTP_AUTHORIZATION:...] on every request */
    if (!hta_env_allowed(r, &lname)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "htaccess: variable \"%V\" is not in htaccess_env_allow", &lname);
        return;
    }

    /*
     * Only variables explicitly declared with set/map/changeable are safe
     * to overwrite.  Apache env vars live in a separate namespace; writing
     * $host/$request_uri/$https from .htaccess would let a customer affect
     * nginx.conf if/map/return checks.
     */
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
    var = ngx_hash_find(&cmcf->variables_hash, hash, lname.data, lname.len);
    if (var == NULL || !(var->flags & NGX_HTTP_VAR_CHANGEABLE)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "htaccess: refusing to overwrite nginx variable \"%V\"", &lname);
        return;
    }

    vv = ngx_http_get_variable(r, &lname, hash);
    if (vv == NULL) return;

    if (do_unset) {
        vv->valid = 0;
        vv->not_found = 1;
        vv->no_cacheable = 0;
        vv->len = 0;
        vv->data = NULL;
    } else {
        if (hta_pstrdup(r, &copy, value) != NGX_OK) return;
        vv->data = copy.data;
        vv->len  = copy.len;
        vv->valid = 1;
        vv->not_found = 0;
        vv->no_cacheable = 0;
    }
}


void
hta_apply_late_env(ngx_http_request_t *r)
{
    hta_req_ctx_t *ctx;
    ngx_str_t     *kv;
    ngx_uint_t     i;

    ctx = ngx_http_get_module_ctx(r, ngx_http_htaccess_module);
    if (ctx == NULL || ctx->env_late == NULL) {
        return;
    }

    kv = ctx->env_late->elts;
    for (i = 0; i < ctx->env_late->nelts; i++) {
        hta_assign_env(r, &kv[2 * i], &kv[2 * i + 1], 0);
    }
}


ngx_int_t
hta_apply_setenvif(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;

    if (h->nsetenvifs == 0) return NGX_OK;

    for (i = 0; i < h->nsetenvifs; i++) {
        hta_setenvif_t *se = &h->setenvifs[i];
        ngx_str_t       test_val = ngx_null_string;

        /* SetEnv / UnsetEnv: no regex, apply unconditionally */
        if (se->unconditional) {
            hta_assign_env(r, &se->env_name, &se->env_value, se->unset);
            continue;
        }

        /* get attribute value */
        if (ngx_strcasecmp(se->attribute.data,
                           (u_char *)"Request_URI") == 0)
        {
            test_val = r->uri;
        } else if (ngx_strcasecmp(se->attribute.data,
                                  (u_char *)"Request_Method") == 0)
        {
            test_val = r->method_name;
        } else if (ngx_strcasecmp(se->attribute.data,
                                  (u_char *)"User-Agent") == 0
                   || ngx_strcasecmp(se->attribute.data,
                                     (u_char *)"HTTP_USER_AGENT") == 0)
        {
            if (r->headers_in.user_agent)
                test_val = r->headers_in.user_agent->value;
        } else if (ngx_strcasecmp(se->attribute.data,
                                  (u_char *)"Referer") == 0
                   || ngx_strcasecmp(se->attribute.data,
                                     (u_char *)"HTTP_REFERER") == 0)
        {
            if (r->headers_in.referer)
                test_val = r->headers_in.referer->value;
        } else if (ngx_strcasecmp(se->attribute.data,
                                  (u_char *)"Host") == 0
                   || ngx_strcasecmp(se->attribute.data,
                                     (u_char *)"HTTP_HOST") == 0)
        {
            if (r->headers_in.host)
                test_val = r->headers_in.host->value;
        } else if (ngx_strcasecmp(se->attribute.data,
                                  (u_char *)"Remote_Addr") == 0
                   || ngx_strcasecmp(se->attribute.data,
                                     (u_char *)"REMOTE_ADDR") == 0)
        {
            test_val = r->connection->addr_text;
        } else {
            /* try as nginx variable */
            ngx_str_t lname;
            lname.len = se->attribute.len;
            lname.data = ngx_pnalloc(r->pool, lname.len);
            if (lname.data) {
                ngx_uint_t                 k;
                ngx_uint_t                 hash;
                ngx_http_variable_value_t *vv;

                for (k = 0; k < lname.len; k++)
                    lname.data[k] = ngx_tolower(se->attribute.data[k]);
                hash = ngx_hash_key(lname.data, lname.len);
                vv = ngx_http_get_variable(r, &lname, hash);
                if (vv && !vv->not_found && vv->len > 0) {
                    test_val.data = vv->data;
                    test_val.len = vv->len;
                }
            }
        }

        /* match regex against attribute value */
        if (se->regex && test_val.len > 0) {
            int       caps[HTA_MAX_CAPTURES];
            ngx_int_t nrc = hta_regex_exec(se->regex, &test_val, caps,
                                           HTA_MAX_CAPTURES);
            if (nrc == HTA_REGEX_ERROR) {
                return NGX_ERROR;
            }
            if (nrc >= 0) {
                ngx_str_t value = se->env_value;
                /* expand $1-$9 from the match into the env value, e.g.
                 * SetEnvIfNoCase ^Authorization$ "(.+)" XAUTH=$1 (Nextcloud) */
                if (!se->unset && se->env_value.len > 0
                    && ngx_strlchr(se->env_value.data,
                           se->env_value.data + se->env_value.len, '$') != NULL)
                {
                    hta_backref_t br;
                    ngx_memzero(&br, sizeof(br));
                    br.rule_subject = test_val;
                    br.rule_caps    = caps;
                    br.rule_ncaps   = (nrc > 0) ? (ngx_uint_t) nrc * 2 : 2;
                    br.have_rule    = 1;
                    if (hta_expand_full(r, &se->env_value, &value, &br)
                        != NGX_OK)
                        value = se->env_value;
                }
                hta_assign_env(r, &se->env_name, &value, se->unset);
            }
        }
    }

    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * RequestHeader - modify r->headers_in for upstream consumers (fastcgi/proxy)
 *
 * Header lookups use ngx_strncasecmp so the source case of incoming header
 * keys does not matter. When an indexed header pointer
 * (r->headers_in.host/user_agent/referer) targets a removed/replaced entry
 * we re-aim it at the live list entry so request-line consumers stay in sync.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_table_elt_t *
hta_find_req_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *elt  = part->elts;
    ngx_uint_t       i;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) return NULL;
            part = part->next;
            elt  = part->elts;
            i = 0;
        }
        if (elt[i].hash == 0) continue;
        if (elt[i].key.len == name->len
            && ngx_strncasecmp(elt[i].key.data, name->data, name->len) == 0)
        {
            return &elt[i];
        }
    }
}

/* Repoint r->headers_in.<known field> pointer to a live list entry (or NULL
 * if removed). Only matters for headers nginx indexes; unknown headers do
 * not need fixup. */
static void
hta_repoint_indexed(ngx_http_request_t *r, ngx_str_t *name,
    ngx_table_elt_t *new_elt)
{
    if (name->len == 4
        && ngx_strncasecmp(name->data, (u_char *)"Host", 4) == 0)
    {
        r->headers_in.host = new_elt;
    } else if (name->len == 7
        && ngx_strncasecmp(name->data, (u_char *)"Referer", 7) == 0)
    {
        r->headers_in.referer = new_elt;
    } else if (name->len == 10
        && ngx_strncasecmp(name->data, (u_char *)"User-Agent", 10) == 0)
    {
        r->headers_in.user_agent = new_elt;
    } else if (name->len == 13
        && ngx_strncasecmp(name->data, (u_char *)"Authorization", 13) == 0)
    {
        r->headers_in.authorization = new_elt;
    } else if (name->len == 6
        && ngx_strncasecmp(name->data, (u_char *)"Cookie", 6) == 0)
    {
#if (nginx_version >= 1023000)
        r->headers_in.cookie = new_elt;
#else
        /* older nginx kept cookies in a list (headers_in.cookies); we leave
         * that array intact and only mark dead entries via hash=0 */
        (void) new_elt;
#endif
    }
}

/* Expand %{NAME} / %{NAME}e / %{NAME}s specifiers in a Header/RequestHeader
 * value by looking NAME up as an nginx variable (covers env vars populated by
 * SetEnv/SetEnvIf and built-in vars), e.g. Nextcloud's
 * "RequestHeader set Authorization %{XAUTH}e". No '%' -> returned unchanged. */
static ngx_int_t
hta_expand_hdr_value(ngx_http_request_t *r, ngx_str_t *src, ngx_str_t *dst)
{
    u_char    *p = src->data, *end = src->data + src->len;
    u_char     res[HTA_MAX_PATH];
    u_char    *d = res;
    ngx_uint_t rlen = 0;

    if (ngx_strlchr(src->data, end, '%') == NULL) { *dst = *src; return NGX_OK; }

    while (p < end && rlen < HTA_MAX_PATH - 1) {
        if (*p == '%' && p + 1 < end && *(p+1) == '{') {
            u_char *ns = p + 2, *ne = ns;
            while (ne < end && *ne != '}') ne++;
            if (ne < end) {
                ngx_str_t  lname;
                ngx_uint_t k, hash;
                ngx_http_variable_value_t *vv;

                p = ne + 1;
                /* optional trailing format specifier: e (env) / s (ssl/var) */
                if (p < end && (*p=='e' || *p=='s' || *p=='E' || *p=='S')) p++;

                lname.len  = ne - ns;
                lname.data = ngx_pnalloc(r->pool, lname.len ? lname.len : 1);
                if (lname.data && lname.len) {
                    for (k = 0; k < lname.len; k++)
                        lname.data[k] = ngx_tolower(ns[k]);
                    hash = ngx_hash_key(lname.data, lname.len);
                    vv = ngx_http_get_variable(r, &lname, hash);
                    if (vv && !vv->not_found && vv->len > 0
                        && rlen + vv->len < HTA_MAX_PATH - 1)
                    {
                        ngx_memcpy(d, vv->data, vv->len);
                        d += vv->len; rlen += vv->len;
                    }
                }
            } else { *d++ = *p++; rlen++; }
        } else { *d++ = *p++; rlen++; }
    }

    *d = '\0';
    dst->data = ngx_pnalloc(r->pool, rlen + 1);
    if (dst->data == NULL) return NGX_ERROR;
    ngx_memcpy(dst->data, res, rlen + 1);
    dst->len = rlen;
    return NGX_OK;
}


static ngx_int_t
hta_framing_header(ngx_str_t *name)
{
    static const char *names[] = {
        "content-length", "transfer-encoding", "connection",
        "keep-alive", "proxy-connection", "upgrade", "te", "trailer", NULL
    };
    ngx_uint_t i;

    for (i = 0; names[i]; i++) {
        size_t len = ngx_strlen(names[i]);
        if (name->len == len
            && ngx_strncasecmp(name->data, (u_char *) names[i], len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static ngx_int_t
hta_proxy_header(ngx_str_t *name)
{
    return (name->len >= 11
            && ngx_strncasecmp(name->data, (u_char *) "x-forwarded-", 11) == 0)
        || (name->len >= 9
            && ngx_strncasecmp(name->data, (u_char *) "x-real-ip", 9) == 0)
        || (name->len >= 9
            && ngx_strncasecmp(name->data, (u_char *) "forwarded", 9) == 0)
        || (name->len >= 5
            && ngx_strncasecmp(name->data, (u_char *) "proxy", 5) == 0)
        || (name->len >= 11
            && ngx_strncasecmp(name->data, (u_char *) "x-original-", 11) == 0);
}

void
hta_apply_request_headers(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t                i;
    hta_header_t             *hd;
    ngx_table_elt_t          *elt;
    ngx_http_hta_loc_conf_t  *lcf;

    if (h->nreq_headers == 0) return;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);

    for (i = 0; i < h->nreq_headers; i++) {
        ngx_str_t name, hv, value;

        hd = &h->req_headers[i];
        if (hta_pstrdup(r, &name, &hd->name) != NGX_OK) return;

        if (hd->action != HTA_HDR_UNSET && hta_framing_header(&name)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "htaccess: refusing to set framing request header \"%V\"",
                &name);
            continue;
        }

        /*
         * Host selects the virtual server and is what upstreams trust for
         * the site name; a second Host line (RequestHeader add/set appends
         * to the list) makes upstreams answer 400.  Never set it from
         * .htaccess.
         */
        if (hd->action != HTA_HDR_UNSET && name.len == 4
            && ngx_strncasecmp(name.data, (u_char *) "host", 4) == 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "htaccess: refusing to set request header \"Host\"");
            continue;
        }

        if (hd->action != HTA_HDR_UNSET
            && (lcf == NULL || !lcf->allow_proxy_headers)
            && hta_proxy_header(&name))
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "htaccess: refusing to forge proxy header \"%V\"", &name);
            continue;
        }

        if (hta_expand_hdr_value(r, &hd->value, &hv) != NGX_OK) hv = hd->value;
        if (hta_pstrdup(r, &value, &hv) != NGX_OK) return;

        if (hta_value_has_crlf(&value)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "htaccess: sanitizing control characters in RequestHeader value");
            hta_value_sanitize(&value);
        }

        switch (hd->action) {
        case HTA_HDR_UNSET:
            elt = hta_find_req_header(r, &name);
            while (elt != NULL) {
                elt->hash = 0;
                elt->value.len = 0;
                elt = hta_find_req_header(r, &name);
            }
            hta_repoint_indexed(r, &name, NULL);
            break;

        case HTA_HDR_SET:
            /* drop all existing copies, then add fresh */
            elt = hta_find_req_header(r, &name);
            while (elt != NULL) {
                elt->hash = 0;
                elt->value.len = 0;
                elt = hta_find_req_header(r, &name);
            }
            /* fall through */
        case HTA_HDR_ADD:
        case HTA_HDR_APPEND:
            elt = ngx_list_push(&r->headers_in.headers);
            if (elt == NULL) return;
            ngx_memzero(elt, sizeof(ngx_table_elt_t));
            elt->key   = name;
            elt->value = value;
            elt->hash  = 1;
            /* nginx hashes lowercase header names for indexed lookups */
            elt->lowcase_key = ngx_pnalloc(r->pool, name.len);
            if (elt->lowcase_key) {
                ngx_uint_t k;
                for (k = 0; k < name.len; k++)
                    elt->lowcase_key[k] = ngx_tolower(name.data[k]);
            }
            hta_repoint_indexed(r, &name, elt);
            break;

        case HTA_HDR_MERGE: {
            /* merge: if entry exists and already contains value, skip; else
             * append a fresh entry like APPEND */
            ngx_table_elt_t *existing = hta_find_req_header(r, &name);
            if (existing && value.len > 0
                && hta_value_contains(&existing->value, &value))
            {
                break;
            }
            elt = ngx_list_push(&r->headers_in.headers);
            if (elt == NULL) return;
            ngx_memzero(elt, sizeof(ngx_table_elt_t));
            elt->key   = name;
            elt->value = value;
            elt->hash  = 1;
            elt->lowcase_key = ngx_pnalloc(r->pool, name.len);
            if (elt->lowcase_key) {
                ngx_uint_t k;
                for (k = 0; k < name.len; k++)
                    elt->lowcase_key[k] = ngx_tolower(name.data[k]);
            }
            hta_repoint_indexed(r, &name, elt);
            break;
        }
        }
    }
}


ngx_int_t
hta_apply_redirects(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;

    if (h->nredirects == 0) return NGX_DECLINED;

    for (i = 0; i < h->nredirects; i++) {
        hta_redirect_t *rd = &h->redirects[i];

        if (rd->is_match && rd->regex) {
            /* RedirectMatch - regex */
            int              caps[HTA_MAX_CAPTURES];
            ngx_int_t        rc;
            ngx_str_t        target;
            ngx_table_elt_t *loc;

            rc = hta_regex_exec(rd->regex, &r->uri, caps,
                                HTA_MAX_CAPTURES);
            if (rc == HTA_REGEX_ERROR) {
                return NGX_ERROR;
            }
            if (rc == NGX_REGEX_NO_MATCHED) continue;

            /* 410 Gone - no target needed */
            if (rd->status == 410) return 410;

            /* Build target with backreferences */
            if (rd->target.len > 0) {
                u_char     res[HTA_MAX_PATH];
                u_char    *p = rd->target.data;
                u_char    *end = p + rd->target.len;
                u_char    *d = res;
                ngx_uint_t rlen = 0;

                while (p < end && rlen < HTA_MAX_PATH - 1) {
                    if (*p == '$' && p + 1 < end && *(p+1) >= '0'
                        && *(p+1) <= '9')
                    {
                        ngx_uint_t n = *(p+1) - '0';
                        p += 2;
                        if (n < (ngx_uint_t)(rc)) {
                            int s = caps[n*2], e = caps[n*2+1];
                            if (s >= 0 && e >= s) {
                                ngx_uint_t blen = e - s;
                                if (rlen + blen < HTA_MAX_PATH - 1) {
                                    ngx_memcpy(d, r->uri.data + s, blen);
                                    d += blen; rlen += blen;
                                }
                            }
                        }
                    } else {
                        *d++ = *p++; rlen++;
                    }
                }
                *d = '\0';
                target.data = ngx_pnalloc(r->pool, rlen + 1);
                if (target.data == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                ngx_memcpy(target.data, res, rlen + 1);
                target.len = rlen;
            } else {
                target = rd->target;
            }

            /* mod_alias appends the original query string to the target */
            if (target.len > 0 && r->args.len > 0
                && ngx_strlchr(target.data, target.data + target.len, '?')
                   == NULL)
            {
                u_char *qt = ngx_pnalloc(r->pool,
                                         target.len + 1 + r->args.len + 1);
                if (qt) {
                    target.len = ngx_sprintf(qt, "%V?%V",
                                             &target, &r->args) - qt;
                    target.data = qt;
                }
            }

            if (hta_value_has_crlf(&target)) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            loc = ngx_list_push(&r->headers_out.headers);
            if (loc == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
            loc->hash = 1;
            ngx_str_set(&loc->key, "Location");
            loc->value = target;
            r->headers_out.status = rd->status;
            r->headers_out.content_length_n = 0;
            return rd->status;

        } else {
            /* Redirect - prefix match */
            if (rd->source.len == 0) continue;

            if (r->uri.len >= rd->source.len
                && ngx_strncmp(r->uri.data, rd->source.data,
                               rd->source.len) == 0)
            {
                ngx_str_t        target;
                ngx_uint_t       tail_len;
                ngx_table_elt_t *loc;

                /* 410 Gone */
                if (rd->status == 410) return 410;

                /* Build target: replace matched prefix with target */
                tail_len = r->uri.len - rd->source.len;
                target.len = rd->target.len + tail_len;
                target.data = ngx_pnalloc(r->pool, target.len + 1);
                if (target.data == NULL)
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;

                ngx_memcpy(target.data, rd->target.data, rd->target.len);
                if (tail_len > 0) {
                    ngx_memcpy(target.data + rd->target.len,
                               r->uri.data + rd->source.len, tail_len);
                }
                target.data[target.len] = '\0';

                /* mod_alias appends the original query string to the target */
                if (target.len > 0 && r->args.len > 0
                    && ngx_strlchr(target.data, target.data + target.len, '?')
                       == NULL)
                {
                    u_char *qt = ngx_pnalloc(r->pool,
                                             target.len + 1 + r->args.len + 1);
                    if (qt) {
                        target.len = ngx_sprintf(qt, "%V?%V",
                                                 &target, &r->args) - qt;
                        target.data = qt;
                    }
                }

                if (hta_value_has_crlf(&target)) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                loc = ngx_list_push(
                                        &r->headers_out.headers);
                if (loc == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                loc->hash = 1;
                ngx_str_set(&loc->key, "Location");
                loc->value = target;
                r->headers_out.status = rd->status;
                r->headers_out.content_length_n = 0;
                return rd->status;
            }
        }
    }

    return NGX_DECLINED;
}
