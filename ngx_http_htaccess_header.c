/*
 * ngx_http_htaccess_header.c - Response header filter
 *
 * Applies Header set/unset/append/add/merge directives,
 * ForceType, AddType, and Expires headers.
 */

#include "ngx_http_htaccess_module.h"


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


void
hta_header_filter_init(ngx_http_output_header_filter_pt next)
{
    ngx_http_next_header_filter = next;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Find and remove existing header by name (for SET operation)
 * ═══════════════════════════════════════════════════════════════════════ */

static void
hta_remove_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *elt;
    ngx_uint_t       j;

    part = &r->headers_out.headers.part;
    elt = part->elts;

    for (j = 0;; j++) {
        if (j >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next; elt = part->elts; j = 0;
        }
        if (elt[j].key.len == name->len
            && ngx_strncasecmp(elt[j].key.data, name->data, name->len) == 0)
        {
            elt[j].hash = 0;
            elt[j].value.len = 0;
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Get file extension from URI
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_str_t
hta_get_extension(ngx_str_t *uri)
{
    ngx_str_t ext = ngx_null_string;
    u_char   *p;

    if (uri->len == 0) return ext;

    for (p = uri->data + uri->len; p > uri->data; ) {
        p--;
        if (*p == '.') {
            ext.data = p + 1;
            ext.len = (uri->data + uri->len) - (p + 1);
            break;
        }
        if (*p == '/') break;
    }
    return ext;
}


/* Set Expires / Cache-Control without duplicating nginx's expires directive
 * entries: reuse r->headers_out.expires and r->headers_out.cache_control. */
static ngx_int_t
hta_set_expires(ngx_http_request_t *r, ngx_int_t ttl)
{
    ngx_table_elt_t *e, *cc, *next;

    e = r->headers_out.expires;
    if (e == NULL) {
        e = ngx_list_push(&r->headers_out.headers);
        if (e == NULL) return NGX_ERROR;
        r->headers_out.expires = e;
        e->next = NULL;
        ngx_str_set(&e->key, "Expires");
    }
    e->hash = 1;
    e->value.data = ngx_pnalloc(r->pool, 32);
    if (e->value.data == NULL) {
        e->hash = 0;
        return NGX_ERROR;
    }
    e->value.len = ngx_http_time(e->value.data, ngx_time() + ttl)
                   - e->value.data;

    cc = r->headers_out.cache_control;
    if (cc == NULL) {
        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            e->hash = 0;
            return NGX_ERROR;
        }
        r->headers_out.cache_control = cc;
        cc->next = NULL;
        ngx_str_set(&cc->key, "Cache-Control");
    } else {
        for (next = cc->next; next; next = next->next) {
            next->hash = 0;
        }
        cc->next = NULL;
    }
    cc->hash = 1;
    cc->value.data = ngx_pnalloc(r->pool, 32);
    if (cc->value.data == NULL) {
        e->hash = 0;
        cc->hash = 0;
        return NGX_ERROR;
    }
    cc->value.len = ngx_sprintf(cc->value.data, "max-age=%i", ttl)
                    - cc->value.data;
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


/* Bounded substring search; header values are not NUL-terminated. */
static ngx_int_t
hta_mem_contains(ngx_str_t *hay, ngx_str_t *needle)
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


/* ═══════════════════════════════════════════════════════════════════════════
 * Apply header directives from a Files block
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_apply_fb_headers(ngx_http_request_t *r, hta_files_block_t *fb)
{
    ngx_uint_t       fhi;
    hta_header_t    *hd;
    ngx_table_elt_t *out;

    for (fhi = 0; fhi < fb->nheaders; fhi++) {
        ngx_str_t                name, value;
        ngx_http_hta_loc_conf_t *lcf;

        hd = &fb->headers[fhi];
        if (hta_pstrdup(r, &name, &hd->name) != NGX_OK
            || hta_pstrdup(r, &value, &hd->value) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (hd->action == HTA_HDR_UNSET
            && hta_protected_security_header(&name)
            && (lcf = ngx_http_get_module_loc_conf(r,
                       ngx_http_htaccess_module)) != NULL
            && !lcf->allow_security_unset)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "htaccess: refusing to unset security header \"%V\"", &name);
            continue;
        }

        if (hta_framing_header(&name)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "htaccess: refusing to set framing header \"%V\"", &name);
            continue;
        }

        if (hd->cond_env.len > 0) {
            ngx_str_t                  lname;
            ngx_uint_t                 k, hash;
            ngx_http_variable_value_t *vv;
            unsigned                   is_set = 0;

            lname.len  = hd->cond_env.len;
            lname.data = ngx_pnalloc(r->pool, lname.len);
            if (lname.data) {
                for (k = 0; k < lname.len; k++)
                    lname.data[k] = ngx_tolower(hd->cond_env.data[k]);
                hash = ngx_hash_key(lname.data, lname.len);
                vv = ngx_http_get_variable(r, &lname, hash);
                is_set = (vv && !vv->not_found && vv->len > 0);
            }
            if (hd->cond_negate ? is_set : !is_set) continue;
        }

        switch (hd->action) {
        case HTA_HDR_SET:
            hta_remove_header(r, &name);
            /* fall through */
        case HTA_HDR_ADD:
            out = ngx_list_push(&r->headers_out.headers);
            if (out == NULL) return NGX_ERROR;
            out->hash = 1;
            out->key = name;
            out->value = value;
            break;
        case HTA_HDR_UNSET:
            hta_remove_header(r, &name);
            break;
        default:
            out = ngx_list_push(&r->headers_out.headers);
            if (out == NULL) return NGX_ERROR;
            out->hash = 1;
            out->key = name;
            out->value = value;
            break;
        }
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Check if basename matches a Files/FilesMatch pattern
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_fb_match(hta_files_block_t *fb, ngx_str_t *bname)
{
    if (fb->is_regex && fb->regex) {
        ngx_int_t rc = hta_regex_exec(fb->regex, bname, NULL, 0);
        if (rc == HTA_REGEX_ERROR) {
            return -1;
        }
        return (rc >= 0);
    }

    return hta_wildcard_match(fb->pattern.data, fb->pattern.len,
                              bname->data, bname->len);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Header filter - main entry point
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_header_filter(ngx_http_request_t *r)
{
    ngx_http_hta_loc_conf_t   *lcf;
    ngx_http_hta_main_conf_t  *mc;
    ngx_http_core_loc_conf_t  *clcf;
    hta_file_list_t           *files;
    ngx_uint_t                 fi, hi, ai, fbi, ati;
    hta_parsed_t              *h;
    hta_header_t              *hd;
    ngx_str_t                  ext, bname, ctype, charset;
    u_char                    *bp, *nv;
    ngx_table_elt_t           *out;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *elt;
    unsigned                   found;
    int                        expires_on = 0;
    ngx_int_t                  expires_default = -1;
    hta_files_block_t         *fb;

    /* skip subrequests — apply .htaccess headers only to the main request */
    if (r != r->main) return ngx_http_next_header_filter(r);

    /*
     * The regex budget of this request is spent (the response is our own
     * 500, or a FilesMatch below failed once already): send the response
     * without .htaccess headers rather than evaluating patterns again.
     */
    {
        hta_req_ctx_t *rctx = ngx_http_get_module_ctx(r,
                                  ngx_http_htaccess_module);
        if (rctx != NULL && (rctx->regex_over || rctx->hdr_failed)) {
            return ngx_http_next_header_filter(r);
        }
    }

    /*
     * .htaccess ErrorDocument performs an internal redirect.  The static
     * handler sets 200 for the error page, so restore the original status
     * (Apache serves custom 404/403 pages with the error status).
     */
    if (r->internal && r->err_status >= NGX_HTTP_BAD_REQUEST
        && (r->headers_out.status == 0
            || r->headers_out.status == NGX_HTTP_OK))
    {
        r->headers_out.status = r->err_status;
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return ngx_http_next_header_filter(r);

    mc  = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!hta_location_supported(clcf)) {
        /* access/rewrite already failed closed; pass the error response */
        return ngx_http_next_header_filter(r);
    }

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL || files->error) {
        return ngx_http_next_header_filter(r);
    }

    for (fi = 0; fi < files->count; fi++) {
        h = hta_get_parsed(r, mc, &files->files[fi]);
        if (h == NULL) {
            /* access/rewrite already failed closed (e.g. a symlinked or
             * out-of-root .htaccess); do not break the error response. */
            return ngx_http_next_header_filter(r);
        }
        if (h->invalid || (lcf->strict && h->has_unknown)) {
            /* Access/rewrite phase already failed closed; do not break the
             * error response through the header filter. */
            return ngx_http_next_header_filter(r);
        }

        /* Header directives */
        for (hi = 0; hi < h->nheaders; hi++) {
            ngx_str_t name, value;

            hd = &h->headers[hi];

            if (hta_pstrdup(r, &name, &hd->name) != NGX_OK
                || hta_pstrdup(r, &value, &hd->value) != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (hta_framing_header(&name)) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "htaccess: refusing to set framing header \"%V\"", &name);
                continue;
            }

            if (hd->action == HTA_HDR_UNSET
                && !lcf->allow_security_unset
                && hta_protected_security_header(&name))
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "htaccess: refusing to unset security header \"%V\"",
                    &name);
                continue;
            }

            /* "env=[!]VAR" condition: apply the header only when the nginx
             * variable is set (or unset, for env=!VAR) */
            if (hd->cond_env.len > 0) {
                ngx_str_t                  lname;
                ngx_uint_t                 k, hash;
                ngx_http_variable_value_t *vv;
                unsigned                   is_set = 0;

                lname.len  = hd->cond_env.len;
                lname.data = ngx_pnalloc(r->pool, lname.len);
                if (lname.data) {
                    for (k = 0; k < lname.len; k++)
                        lname.data[k] = ngx_tolower(hd->cond_env.data[k]);
                    hash = ngx_hash_key(lname.data, lname.len);
                    vv = ngx_http_get_variable(r, &lname, hash);
                    is_set = (vv && !vv->not_found && vv->len > 0);
                }
                if (hd->cond_negate ? is_set : !is_set) continue;
            }

            switch (hd->action) {
            case HTA_HDR_SET:
                hta_remove_header(r, &name);
                /* fall through */
            case HTA_HDR_ADD:
                out = ngx_list_push(&r->headers_out.headers);
                if (out == NULL) return NGX_ERROR;
                out->hash = 1;
                out->key = name;
                out->value = value;
                break;

            case HTA_HDR_UNSET:
                hta_remove_header(r, &name);
                break;

            case HTA_HDR_APPEND:
            case HTA_HDR_MERGE:
                if (value.len == 0) {
                    /* invalid "Header merge Name" without value */
                    break;
                }

                part = &r->headers_out.headers.part;
                elt = part->elts;
                found = 0;
                for (ai = 0;; ai++) {
                    if (ai >= part->nelts) {
                        if (part->next == NULL) break;
                        part = part->next; elt = part->elts; ai = 0;
                    }
                    if (elt[ai].hash == 0) continue;
                    if (elt[ai].key.len == name.len
                        && ngx_strncasecmp(elt[ai].key.data, name.data,
                                           name.len) == 0)
                    {
                        if (hd->action == HTA_HDR_MERGE
                            && hta_mem_contains(&elt[ai].value, &value))
                        {
                            found = 1; break;
                        }
                        nv = ngx_pnalloc(r->pool,
                            elt[ai].value.len + 2 + value.len + 1);
                        if (nv) {
                            elt[ai].value.len = ngx_sprintf(nv, "%V, %V",
                                &elt[ai].value, &value) - nv;
                            elt[ai].value.data = nv;
                        }
                        found = 1; break;
                    }
                }
                if (!found) {
                    out = ngx_list_push(&r->headers_out.headers);
                    if (out == NULL) return NGX_ERROR;
                    out->hash = 1;
                    out->key = name;
                    out->value = value;
                }
                break;
            }
        }

        /* ForceType */
        if (h->force_type.len > 0) {
            if (hta_pstrdup(r, &ctype, &h->force_type) != NGX_OK) {
                return NGX_ERROR;
            }
            r->headers_out.content_type = ctype;
            r->headers_out.content_type_len = ctype.len;
        }

        /* AddType - match file extension */
        if (h->naddtypes > 0) {
            ext = hta_get_extension(&r->uri);
            if (ext.len > 0) {
                for (ai = 0; ai < h->naddtypes; ai++) {
                    if (ext.len == h->addtypes[ai].extension.len
                        && ngx_strncasecmp(ext.data,
                                           h->addtypes[ai].extension.data,
                                           ext.len) == 0)
                    {
                        if (hta_pstrdup(r, &ctype,
                                        &h->addtypes[ai].mime_type) != NGX_OK)
                        {
                            return NGX_ERROR;
                        }
                        r->headers_out.content_type = ctype;
                        r->headers_out.content_type_len = ctype.len;
                        break;
                    }
                }
            }
        }

        /* DefaultType - apply when no content type is set */
        if (h->default_type.len > 0
            && r->headers_out.content_type.len == 0)
        {
            if (hta_pstrdup(r, &ctype, &h->default_type) != NGX_OK) {
                return NGX_ERROR;
            }
            r->headers_out.content_type = ctype;
            r->headers_out.content_type_len = ctype.len;
        }

        /* AddDefaultCharset - append charset to Content-Type */
        if (h->default_charset.len > 0
            && r->headers_out.content_type.len > 0)
        {
            if (r->headers_out.content_type.len >= 5
                && ngx_strncasecmp(r->headers_out.content_type.data,
                                   (u_char *)"text/", 5) == 0
                && r->headers_out.charset.len == 0)
            {
                if (hta_pstrdup(r, &charset, &h->default_charset) != NGX_OK) {
                    return NGX_ERROR;
                }
                r->headers_out.charset = charset;
            }
        }

        /* <Files>/<FilesMatch> block headers and types */
        if (h->nfiles_blocks > 0) {
            ext = hta_get_extension(&r->uri);
            bname = r->uri;
            for (bp = r->uri.data + r->uri.len; bp > r->uri.data; ) {
                bp--;
                if (*bp == '/') {
                    bname.data = bp + 1;
                    bname.len = (r->uri.data + r->uri.len) - (bp + 1);
                    break;
                }
            }

            for (fbi = 0; fbi < h->nfiles_blocks; fbi++) {
                fb = &h->files_blocks[fbi];

                {
                    ngx_int_t mrc = hta_fb_match(fb, &bname);
                    if (mrc == -1) {
                        hta_req_ctx_t *rctx = hta_req_ctx(r);
                        if (rctx != NULL) rctx->hdr_failed = 1;
                        return ngx_http_filter_finalize_request(r,
                                   &ngx_http_htaccess_module,
                                   NGX_HTTP_INTERNAL_SERVER_ERROR);
                    }
                    if (!mrc) continue;
                }

                /* ForceType */
                if (fb->force_type.len > 0) {
                    if (hta_pstrdup(r, &ctype, &fb->force_type) != NGX_OK) {
                        return NGX_ERROR;
                    }
                    r->headers_out.content_type = ctype;
                    r->headers_out.content_type_len = ctype.len;
                }

                /* AddType */
                if (fb->naddtypes > 0 && ext.len > 0) {
                    for (ati = 0; ati < fb->naddtypes; ati++) {
                        if (ext.len == fb->addtypes[ati].extension.len
                            && ngx_strncasecmp(ext.data,
                                   fb->addtypes[ati].extension.data,
                                   ext.len) == 0)
                        {
                            if (hta_pstrdup(r, &ctype,
                                    &fb->addtypes[ati].mime_type) != NGX_OK)
                            {
                                return NGX_ERROR;
                            }
                            r->headers_out.content_type = ctype;
                            r->headers_out.content_type_len = ctype.len;
                            break;
                        }
                    }
                }

                /* Headers */
                if (hta_apply_fb_headers(r, fb) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }

        /* ExpiresActive state is merged root -> leaf; the header itself is
         * emitted once after the loop so a child "ExpiresActive Off" removes
         * a parent-generated header instead of leaving a stale one. */
        if (h->expires_active_set) {
            expires_on = h->expires_active;
        }
        if (h->expires_default > 0) {
            expires_default = h->expires_default;
        }
    }

    if (expires_on) {
        ngx_int_t   ttl = -1;
        ngx_uint_t  fi2;

        if (r->headers_out.content_type.len > 0) {
            for (fi2 = files->count; fi2 > 0 && ttl <= 0; fi2--) {
                hta_parsed_t *h2 = hta_get_parsed(r, mc,
                                                 &files->files[fi2 - 1]);
                ngx_uint_t    ej;

                if (h2 == NULL || h2->invalid) continue;

                for (ej = 0; ej < h2->nexpires; ej++) {
                    if (r->headers_out.content_type.len
                            >= h2->expires[ej].mime_type.len
                        && ngx_strncasecmp(
                               r->headers_out.content_type.data,
                               h2->expires[ej].mime_type.data,
                               h2->expires[ej].mime_type.len) == 0)
                    {
                        ttl = h2->expires[ej].seconds;
                        break;
                    }
                }
            }
        }

        if (ttl <= 0) ttl = expires_default;

        if (ttl > 0 && hta_set_expires(r, ttl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return ngx_http_next_header_filter(r);
}
