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
        hd = &fb->headers[fhi];
        switch (hd->action) {
        case HTA_HDR_SET:
            hta_remove_header(r, &hd->name);
            /* fall through */
        case HTA_HDR_ADD:
            out = ngx_list_push(&r->headers_out.headers);
            if (out == NULL) return NGX_ERROR;
            out->hash = 1;
            out->key = hd->name;
            out->value = hd->value;
            break;
        case HTA_HDR_UNSET:
            hta_remove_header(r, &hd->name);
            break;
        default:
            out = ngx_list_push(&r->headers_out.headers);
            if (out == NULL) return NGX_ERROR;
            out->hash = 1;
            out->key = hd->name;
            out->value = hd->value;
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
    ngx_uint_t plen, slen;

    if (fb->is_regex && fb->regex) {
        return (ngx_regex_exec(fb->regex, bname, NULL, 0) >= 0);
    }

    if (fb->pattern.len == bname->len
        && ngx_strncasecmp(fb->pattern.data, bname->data, bname->len) == 0)
    {
        return 1;
    }

    if (fb->pattern.len > 1
        && fb->pattern.data[fb->pattern.len - 1] == '*')
    {
        plen = fb->pattern.len - 1;
        if (bname->len >= plen
            && ngx_strncasecmp(bname->data, fb->pattern.data, plen) == 0)
        {
            return 1;
        }
    }

    if (fb->pattern.len > 1 && fb->pattern.data[0] == '*') {
        slen = fb->pattern.len - 1;
        if (bname->len >= slen
            && ngx_strncasecmp(bname->data + bname->len - slen,
                               fb->pattern.data + 1, slen) == 0)
        {
            return 1;
        }
    }

    return 0;
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
    ngx_uint_t                 fi, hi, ai, ei, fbi, ati;
    hta_parsed_t              *h;
    hta_header_t              *hd;
    ngx_str_t                  ext, bname;
    u_char                    *bp, *nv;
    ngx_table_elt_t           *out, *cc, *exp;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *elt;
    unsigned                   found;
    ngx_int_t                  ttl;
    time_t                     expires_time;
    hta_files_block_t         *fb;

    /* skip subrequests — apply .htaccess headers only to the main request */
    if (r != r->main) return ngx_http_next_header_filter(r);

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return ngx_http_next_header_filter(r);

    mc  = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->root.len == 0) return ngx_http_next_header_filter(r);

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL) return ngx_http_next_header_filter(r);

    for (fi = 0; fi < files->count; fi++) {
        h = hta_get_parsed(r, mc, &files->files[fi]);
        if (h == NULL) continue;

        /* Header directives */
        for (hi = 0; hi < h->nheaders; hi++) {
            hd = &h->headers[hi];

            switch (hd->action) {
            case HTA_HDR_SET:
                hta_remove_header(r, &hd->name);
                /* fall through */
            case HTA_HDR_ADD:
                out = ngx_list_push(&r->headers_out.headers);
                if (out == NULL) return NGX_ERROR;
                out->hash = 1;
                out->key = hd->name;
                out->value = hd->value;
                break;

            case HTA_HDR_UNSET:
                hta_remove_header(r, &hd->name);
                break;

            case HTA_HDR_APPEND:
            case HTA_HDR_MERGE:
                part = &r->headers_out.headers.part;
                elt = part->elts;
                found = 0;
                for (ai = 0;; ai++) {
                    if (ai >= part->nelts) {
                        if (part->next == NULL) break;
                        part = part->next; elt = part->elts; ai = 0;
                    }
                    if (elt[ai].key.len == hd->name.len
                        && ngx_strncasecmp(elt[ai].key.data, hd->name.data,
                                           hd->name.len) == 0)
                    {
                        if (hd->action == HTA_HDR_MERGE
                            && ngx_strnstr(elt[ai].value.data,
                                           (char *)hd->value.data,
                                           elt[ai].value.len) != NULL)
                        {
                            found = 1; break;
                        }
                        nv = ngx_pnalloc(r->pool,
                            elt[ai].value.len + 2 + hd->value.len + 1);
                        if (nv) {
                            elt[ai].value.len = ngx_sprintf(nv, "%V, %V",
                                &elt[ai].value, &hd->value) - nv;
                            elt[ai].value.data = nv;
                        }
                        found = 1; break;
                    }
                }
                if (!found) {
                    out = ngx_list_push(&r->headers_out.headers);
                    if (out == NULL) return NGX_ERROR;
                    out->hash = 1;
                    out->key = hd->name;
                    out->value = hd->value;
                }
                break;
            }
        }

        /* ForceType */
        if (h->force_type.len > 0) {
            r->headers_out.content_type = h->force_type;
            r->headers_out.content_type_len = h->force_type.len;
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
                        r->headers_out.content_type =
                            h->addtypes[ai].mime_type;
                        r->headers_out.content_type_len =
                            h->addtypes[ai].mime_type.len;
                        break;
                    }
                }
            }
        }

        /* DefaultType - apply when no content type is set */
        if (h->default_type.len > 0
            && r->headers_out.content_type.len == 0)
        {
            r->headers_out.content_type = h->default_type;
            r->headers_out.content_type_len = h->default_type.len;
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
                r->headers_out.charset = h->default_charset;
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

                if (!hta_fb_match(fb, &bname)) continue;

                /* ForceType */
                if (fb->force_type.len > 0) {
                    r->headers_out.content_type = fb->force_type;
                    r->headers_out.content_type_len = fb->force_type.len;
                }

                /* AddType */
                if (fb->naddtypes > 0 && ext.len > 0) {
                    for (ati = 0; ati < fb->naddtypes; ati++) {
                        if (ext.len == fb->addtypes[ati].extension.len
                            && ngx_strncasecmp(ext.data,
                                   fb->addtypes[ati].extension.data,
                                   ext.len) == 0)
                        {
                            r->headers_out.content_type =
                                fb->addtypes[ati].mime_type;
                            r->headers_out.content_type_len =
                                fb->addtypes[ati].mime_type.len;
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

        /* Expires - set Cache-Control and Expires headers */
        if (h->expires_active) {
            ttl = -1;

            /* Check ExpiresByType first */
            if (h->nexpires > 0 && r->headers_out.content_type.len > 0) {
                for (ei = 0; ei < h->nexpires; ei++) {
                    if (r->headers_out.content_type.len
                            >= h->expires[ei].mime_type.len
                        && ngx_strncasecmp(
                               r->headers_out.content_type.data,
                               h->expires[ei].mime_type.data,
                               h->expires[ei].mime_type.len) == 0)
                    {
                        ttl = h->expires[ei].seconds;
                        break;
                    }
                }
            }

            /* Fall back to ExpiresDefault */
            if (ttl < 0 && h->expires_default > 0) {
                ttl = h->expires_default;
            }

            if (ttl > 0) {
                /* Set Cache-Control: max-age=N */
                cc = ngx_list_push(&r->headers_out.headers);
                if (cc) {
                    cc->hash = 1;
                    ngx_str_set(&cc->key, "Cache-Control");
                    cc->value.data = ngx_pnalloc(r->pool, 32);
                    if (cc->value.data) {
                        cc->value.len = ngx_sprintf(cc->value.data,
                            "max-age=%i", ttl) - cc->value.data;
                    }
                }

                /* Set Expires header */
                exp = ngx_list_push(&r->headers_out.headers);
                if (exp) {
                    exp->hash = 1;
                    ngx_str_set(&exp->key, "Expires");
                    exp->value.data = ngx_pnalloc(r->pool, 32);
                    if (exp->value.data) {
                        expires_time = ngx_time() + ttl;
                        exp->value.len = ngx_http_time(exp->value.data,
                                                        expires_time)
                                         - exp->value.data;
                    }
                }
            }
        }
    }

    return ngx_http_next_header_filter(r);
}
