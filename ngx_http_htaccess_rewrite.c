/*
 * ngx_http_htaccess_rewrite.c - Rewrite engine
 *
 * Variable expansion, backreference substitution, condition evaluation,
 * RewriteRule application, DirectoryIndex handling.
 */

#include "ngx_http_htaccess_module.h"
#include <sys/stat.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * Variable expansion - %{VAR_NAME}
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_expand_vars(ngx_http_request_t *r, ngx_str_t *src, ngx_str_t *dst)
{
    u_char  res[HTA_MAX_PATH];
    u_char *p = src->data, *end = src->data + src->len, *d = res;
    ngx_uint_t rlen = 0;

    while (p < end && rlen < HTA_MAX_PATH - 1) {
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

            if (vlen == 11 && ngx_strncasecmp(vs, (u_char *)"REQUEST_URI", 11) == 0) {
                val = r->uri;
            } else if (vlen == 16 && ngx_strncasecmp(vs, (u_char *)"REQUEST_FILENAME", 16) == 0) {
                ngx_http_core_loc_conf_t *clcf;
                u_char *tmp;
                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
                /* Security: reject URIs with ".." to prevent path traversal.
                 * Use length-aware scan — r->uri is ngx_str_t, not NUL-terminated */
                if (ngx_strnstr(r->uri.data, "..", r->uri.len) == NULL) {
                    tmp = ngx_pnalloc(r->pool, clcf->root.len + r->uri.len + 1);
                    if (tmp) {
                        ngx_memcpy(tmp, clcf->root.data, clcf->root.len);
                        ngx_memcpy(tmp + clcf->root.len, r->uri.data, r->uri.len);
                        tmp[clcf->root.len + r->uri.len] = '\0';
                        val.data = tmp; val.len = clcf->root.len + r->uri.len;
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
#if (NGX_HTTP_SSL)
                val.data = (u_char *)(r->connection->ssl ? "on" : "off");
                val.len = r->connection->ssl ? 2 : 3;
#else
                ngx_str_set(&val, "off");
#endif
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
                goto nginx_var_fallback;
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

            if (val.len > 0 && rlen + val.len < HTA_MAX_PATH - 1) {
                ngx_memcpy(d, val.data, val.len);
                d += val.len; rlen += val.len;
            }
        } else {
            *d++ = *p++; rlen++;
        }
    }

    *d = '\0';
    dst->data = ngx_pnalloc(r->pool, rlen + 1);
    if (dst->data == NULL) return NGX_ERROR;
    ngx_memcpy(dst->data, res, rlen + 1);
    dst->len = rlen;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Substitution with backreferences ($1..$9) and variables (%{VAR})
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_substitute(ngx_http_request_t *r, hta_rule_t *rule, ngx_str_t *uri,
    int *caps, ngx_uint_t ncaps)
{
    u_char  res[HTA_MAX_PATH];
    u_char *p, *end, *d;
    ngx_uint_t rlen = 0;

    if (ngx_strcmp(rule->substitution.data, "-") == 0)
        return NGX_DECLINED;

    p = rule->substitution.data;
    end = p + rule->substitution.len;
    d = res;

    while (p < end && rlen < HTA_MAX_PATH - 1) {
        if (*p == '$' && p + 1 < end && *(p+1) >= '0' && *(p+1) <= '9') {
            ngx_uint_t n = *(p+1) - '0';
            p += 2;
            if (n < ncaps / 2) {
                int s = caps[n*2], e = caps[n*2+1];
                if (s >= 0 && e >= s) {
                    ngx_uint_t blen = e - s;
                    if (rlen + blen < HTA_MAX_PATH - 1) {
                        ngx_memcpy(d, uri->data + s, blen);
                        d += blen; rlen += blen;
                    }
                }
            }
        } else if (*p == '%' && p + 1 < end && *(p+1) == '{') {
            ngx_str_t vref, exp;
            u_char *vstart = p;
            while (p < end && *p != '}') p++;
            if (p < end) p++;
            vref.data = vstart; vref.len = p - vstart;
            if (hta_expand_vars(r, &vref, &exp) == NGX_OK && exp.len > 0) {
                if (rlen + exp.len < HTA_MAX_PATH - 1) {
                    ngx_memcpy(d, exp.data, exp.len);
                    d += exp.len; rlen += exp.len;
                }
            }
        } else {
            *d++ = *p++; rlen++;
        }
    }

    *d = '\0';
    uri->data = ngx_pnalloc(r->pool, rlen + 1);
    if (uri->data == NULL) return NGX_ERROR;
    ngx_memcpy(uri->data, res, rlen + 1);
    uri->len = rlen;
    return NGX_OK;
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
hta_eval_conds(ngx_http_request_t *r, hta_rule_t *rule)
{
    ngx_uint_t i;
    ngx_int_t  final_result = 1;
    ngx_int_t  group_result = 0;
    unsigned   in_or_group = 0;

    if (rule->nconds == 0) return NGX_OK;

    for (i = 0; i < rule->nconds; i++) {
        hta_cond_t *c;
        ngx_int_t   match;
        ngx_str_t   expanded;

        c = &rule->conds[i];
        match = 0;
        if (hta_expand_vars(r, &c->test_string, &expanded) != NGX_OK)
            return NGX_ERROR;

        switch (c->test_type) {
        case HTA_TEST_REGEX:
            if (c->regex) {
                int caps[HTA_MAX_CAPTURES];
                match = (ngx_regex_exec(c->regex, &expanded, caps,
                                        HTA_MAX_CAPTURES) >= 0);
            }
            break;
        case HTA_TEST_FILE: {
            ngx_file_info_t fi;
            /* Security: reject path traversal in file tests */
            if (ngx_strstr(expanded.data, "..") != NULL) break;
            match = (ngx_file_info(expanded.data, &fi) == 0
                     && ngx_is_file(&fi));
            break;
        }
        case HTA_TEST_DIR: {
            ngx_file_info_t fi;
            if (ngx_strstr(expanded.data, "..") != NULL) break;
            match = (ngx_file_info(expanded.data, &fi) == 0
                     && ngx_is_dir(&fi));
            break;
        }
        case HTA_TEST_LINK: {
            struct stat st;
            if (ngx_strstr(expanded.data, "..") != NULL) break;
            match = (lstat((char *)expanded.data, &st) == 0
                     && S_ISLNK(st.st_mode));
            break;
        }
        case HTA_TEST_EXISTS: {
            ngx_file_info_t fi;
            if (ngx_strstr(expanded.data, "..") != NULL) break;
            match = (ngx_file_info(expanded.data, &fi) == 0);
            break;
        }
        case HTA_TEST_SIZE: {
            ngx_file_info_t fi;
            if (ngx_strstr(expanded.data, "..") != NULL) break;
            match = (ngx_file_info(expanded.data, &fi) == 0
                     && ngx_file_size(&fi) > 0);
            break;
        }
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

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    for (i = 0; i < h->nindex; i++) {
        ngx_int_t plen = ngx_snprintf(path, sizeof(path) - 1,
                                       "%V%V%V", &clcf->root, &r->uri,
                                       &h->index_files[i]) - path;
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

    if (!h->rewrite_on || h->nrules == 0) return NGX_DECLINED;

    /* strip leading slash / rewrite base for per-dir context */
    uri = r->uri;
    if (uri.len > 0 && uri.data[0] == '/') {
        if (h->rewrite_base.len > 0 && uri.len >= h->rewrite_base.len &&
            ngx_strncmp(uri.data, h->rewrite_base.data,
                        h->rewrite_base.len) == 0)
        {
            uri.data += h->rewrite_base.len;
            uri.len  -= h->rewrite_base.len;
        } else {
            uri.data++;
            uri.len--;
        }
    }

    for (i = 0; i < h->nrules; i++) {
        hta_rule_t *rule;
        ngx_str_t   nuri;
        ngx_str_t   nargs;
        u_char     *q;

        rule = &h->rules[i];

        if (skip > 0) { skip--; continue; }

        /* check conditions */
        rc = hta_eval_conds(r, rule);
        if (rc == NGX_DECLINED) {
            if (rule->flags & HTA_F_CHAIN) {
                ngx_uint_t j = i + 1;
                while (j < h->nrules && h->rules[j-1].flags & HTA_F_CHAIN) j++;
                i = j - 1;
            }
            continue;
        }
        if (rc == NGX_ERROR) return NGX_ERROR;

        /* match pattern */
        rc = ngx_regex_exec(rule->regex, &uri, caps, HTA_MAX_CAPTURES);
        if (rc == NGX_REGEX_NO_MATCHED) {
            if (rule->flags & HTA_F_CHAIN) {
                ngx_uint_t j = i + 1;
                while (j < h->nrules && h->rules[j-1].flags & HTA_F_CHAIN) j++;
                i = j - 1;
            }
            continue;
        }
        if (rc < 0) continue;

        /* === matched === */

        /* apply [E=key:val] flag - set nginx variable */
        if (rule->flags & HTA_F_ENV && rule->env_key.len > 0) {
            ngx_str_t vname;
            vname.len = rule->env_key.len;
            vname.data = ngx_pnalloc(r->pool, vname.len);
            if (vname.data) {
                ngx_uint_t                 k;
                ngx_uint_t                 hash;
                ngx_http_variable_value_t *vv;

                for (k = 0; k < vname.len; k++)
                    vname.data[k] = ngx_tolower(rule->env_key.data[k]);
                hash = ngx_hash_key(vname.data, vname.len);
                vv = ngx_http_get_variable(r, &vname, hash);
                if (vv) {
                    vv->data = rule->env_val.data;
                    vv->len = rule->env_val.len;
                    vv->valid = 1;
                    vv->not_found = 0;
                    vv->no_cacheable = 0;
                }
            }
        }

        if (rule->flags & HTA_F_FORBIDDEN) return NGX_HTTP_FORBIDDEN;
        if (rule->flags & HTA_F_GONE)      return 410;

        /* apply substitution */
        nuri = uri;
        rc = hta_substitute(r, rule, &nuri, caps, rc * 2);
        if (rc == NGX_DECLINED) {
            if (rule->flags & (HTA_F_LAST | HTA_F_END)) break;
            if (rule->flags & HTA_F_SKIP) skip = rule->skip_count;
            continue;
        }
        if (rc == NGX_ERROR) return NGX_ERROR;

        if (rule->flags & HTA_F_SKIP) skip = rule->skip_count;

        /* external redirect? */
        if ((rule->flags & HTA_F_REDIRECT) ||
            (nuri.len >= 7 &&
             (ngx_strncasecmp(nuri.data, (u_char *)"http://", 7) == 0 ||
              ngx_strncasecmp(nuri.data, (u_char *)"https://", 8) == 0)))
        {
            ngx_int_t        code = rule->redirect_code;
            ngx_table_elt_t *loc;

            if (code < 300 || code > 399) code = 302;

            /* QSA */
            if ((rule->flags & HTA_F_QSA) && r->args.len > 0) {
                u_char  sep = ngx_strchr(nuri.data, '?') ? '&' : '?';
                u_char *quri = ngx_pnalloc(r->pool,
                                           nuri.len + 1 + r->args.len + 1);
                if (quri) {
                    nuri.len = ngx_sprintf(quri, "%V%c%V",
                                           &nuri, sep, &r->args) - quri;
                    nuri.data = quri;
                }
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
                pre = ngx_pnalloc(r->pool, 1 + nuri.len + 1);
                if (pre) {
                    pre[0] = '/';
                    ngx_memcpy(pre + 1, nuri.data, nuri.len);
                    pre[1 + nuri.len] = '\0';
                    nuri.data = pre; nuri.len = 1 + nuri.len;
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
        uri = nuri;
        if (uri.len > 0 && uri.data[0] == '/') {
            if (h->rewrite_base.len > 0 && uri.len >= h->rewrite_base.len &&
                ngx_strncmp(uri.data, h->rewrite_base.data,
                            h->rewrite_base.len) == 0)
            {
                uri.data += h->rewrite_base.len;
                uri.len  -= h->rewrite_base.len;
            } else {
                uri.data++; uri.len--;
            }
        }
    }

    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Redirect / RedirectMatch / RedirectPermanent / RedirectTemp
 *
 * Applies simple URL redirects (prefix match or regex match).
 * Called before RewriteRule processing.
 * ═══════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════════
 * ErrorDocument - redirect to custom error page for a given status code
 * Returns the original status if no ErrorDocument is configured
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_check_errdoc(ngx_http_request_t *r, hta_parsed_t *h, ngx_int_t status)
{
    ngx_uint_t i;

    if (h->nerrdocs == 0 || status < 400) return status;

    for (i = 0; i < h->nerrdocs; i++) {
        if (h->errdocs[i].code == status) {
            if (h->errdocs[i].is_url) {
                ngx_table_elt_t *loc;
                if (h->errdocs[i].response.data[0] == '/') {
                    /* internal URL - do internal redirect */
                    return ngx_http_internal_redirect(r,
                        &h->errdocs[i].response, &r->args);
                }
                /* external URL - 302 redirect */
                loc = ngx_list_push(
                    &r->headers_out.headers);
                if (loc == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
                loc->hash = 1;
                ngx_str_set(&loc->key, "Location");
                loc->value = h->errdocs[i].response;
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

void
hta_apply_setenvif(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;

    if (h->nsetenvifs == 0) return;

    for (i = 0; i < h->nsetenvifs; i++) {
        hta_setenvif_t *se = &h->setenvifs[i];
        ngx_str_t test_val = ngx_null_string;

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
            if (ngx_regex_exec(se->regex, &test_val, NULL, 0) >= 0) {
                /* set the nginx variable */
                ngx_str_t vname;
                vname.len = se->env_name.len;
                vname.data = ngx_pnalloc(r->pool, vname.len);
                if (vname.data) {
                    ngx_uint_t                 k;
                    ngx_uint_t                 hash;
                    ngx_http_variable_value_t *vv;

                    for (k = 0; k < vname.len; k++)
                        vname.data[k] = ngx_tolower(se->env_name.data[k]);
                    hash = ngx_hash_key(vname.data, vname.len);
                    vv = ngx_http_get_variable(r, &vname, hash);
                    if (vv) {
                        vv->data = se->env_value.data;
                        vv->len = se->env_value.len;
                        vv->valid = 1;
                        vv->not_found = 0;
                        vv->no_cacheable = 0;
                    }
                }
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

            rc = ngx_regex_exec(rd->regex, &r->uri, caps,
                                HTA_MAX_CAPTURES);
            if (rc < 0) continue;

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
