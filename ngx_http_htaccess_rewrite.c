/*
 * ngx_http_htaccess_rewrite.c - Rewrite engine
 *
 * Variable expansion, backreference substitution, condition evaluation,
 * RewriteRule application, DirectoryIndex handling.
 */

#include "ngx_http_htaccess_module.h"
#include <sys/stat.h>


/* defined later in this file - used by %{HTTP:Header} expansion */
static ngx_table_elt_t *hta_find_req_header(ngx_http_request_t *r,
    ngx_str_t *name);


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
                val = r->uri;
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
    u_char     res[HTA_MAX_PATH];
    u_char    *d = res;
    ngx_uint_t rlen = 0;

    while (p < end && rlen < HTA_MAX_PATH - 1) {
        if (*p == '$' && p + 1 < end && *(p+1) >= '0' && *(p+1) <= '9'
            && br && br->have_rule)
        {
            ngx_uint_t n = *(p+1) - '0';
            p += 2;
            if (n < br->rule_ncaps / 2) {
                int s = br->rule_caps[n*2], e = br->rule_caps[n*2+1];
                if (s >= 0 && e >= s) {
                    ngx_uint_t blen = e - s;
                    if (rlen + blen < HTA_MAX_PATH - 1) {
                        ngx_memcpy(d, br->rule_subject.data + s, blen);
                        d += blen; rlen += blen;
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
                    ngx_uint_t blen = e - s;
                    if (rlen + blen < HTA_MAX_PATH - 1) {
                        ngx_memcpy(d, br->cond_subject.data + s, blen);
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
    dst->data = ngx_pnalloc(r->pool, rlen + 1);
    if (dst->data == NULL) return NGX_ERROR;
    ngx_memcpy(dst->data, res, rlen + 1);
    dst->len = rlen;
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

    if (rule->nconds == 0) return NGX_OK;

    for (i = 0; i < rule->nconds; i++) {
        hta_cond_t *c;
        ngx_int_t   match;
        ngx_str_t   expanded;
        ngx_str_t   rhs;

        c = &rule->conds[i];
        match = 0;
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
                ngx_int_t nrc = ngx_regex_exec(c->regex, &expanded, lcaps,
                                               HTA_MAX_CAPTURES);
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
 * FallbackResource - serve a front controller when the request maps to no
 * existing file (mod_dir). $request_uri stays the original, so the app still
 * sees the routed path (same as nginx `try_files $uri /index.php`).
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_int_t
hta_apply_fallback(ngx_http_request_t *r, ngx_str_t *fallback)
{
    ngx_str_t       path;
    size_t          rl;
    u_char         *last;
    ngx_file_info_t fi;

    if (fallback->len == 0) return NGX_DECLINED;

    /* avoid an internal-redirect loop onto the fallback itself */
    if (r->uri.len == fallback->len
        && ngx_strncmp(r->uri.data, fallback->data, fallback->len) == 0)
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

    return ngx_http_internal_redirect(r, fallback, &r->args);
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

        ngx_memzero(&br, sizeof(br));
        br.rule_subject = uri;
        br.rule_caps    = caps;
        br.rule_ncaps   = (rc > 0) ? (ngx_uint_t) rc * 2 : 2;
        br.have_rule    = 1;

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
                    /* the E= value may reference %{VAR}/$N/%N, e.g.
                     * [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}] */
                    ngx_str_t ev;
                    if (hta_expand_full(r, &rule->env_val, &ev, &br) != NGX_OK)
                        ev = rule->env_val;
                    vv->data = ev.data;
                    vv->len = ev.len;
                    vv->valid = 1;
                    vv->not_found = 0;
                    vv->no_cacheable = 0;
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
        changed = 1;
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

/* Set or clear an nginx variable given its case-preserving name.
 * On set, env_value is the new value; on unset, the variable is marked
 * not_found so consumers see it as absent (matching Apache UnsetEnv).
 */
static void
hta_assign_env(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value,
    unsigned do_unset)
{
    ngx_str_t                  lname;
    ngx_uint_t                 k, hash;
    ngx_http_variable_value_t *vv;

    if (name->len == 0) return;

    lname.len = name->len;
    lname.data = ngx_pnalloc(r->pool, lname.len);
    if (lname.data == NULL) return;
    for (k = 0; k < lname.len; k++)
        lname.data[k] = ngx_tolower(name->data[k]);

    hash = ngx_hash_key(lname.data, lname.len);
    vv = ngx_http_get_variable(r, &lname, hash);
    if (vv == NULL) return;

    if (do_unset) {
        vv->valid = 0;
        vv->not_found = 1;
        vv->no_cacheable = 0;
        vv->len = 0;
        vv->data = NULL;
    } else {
        vv->data = value->data;
        vv->len  = value->len;
        vv->valid = 1;
        vv->not_found = 0;
        vv->no_cacheable = 0;
    }
}


void
hta_apply_setenvif(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t i;

    if (h->nsetenvifs == 0) return;

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
            ngx_int_t nrc = ngx_regex_exec(se->regex, &test_val, caps,
                                           HTA_MAX_CAPTURES);
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


void
hta_apply_request_headers(ngx_http_request_t *r, hta_parsed_t *h)
{
    ngx_uint_t       i;
    hta_header_t    *hd;
    ngx_table_elt_t *elt;

    if (h->nreq_headers == 0) return;

    for (i = 0; i < h->nreq_headers; i++) {
        ngx_str_t hv;

        hd = &h->req_headers[i];
        if (hta_expand_hdr_value(r, &hd->value, &hv) != NGX_OK) hv = hd->value;

        switch (hd->action) {
        case HTA_HDR_UNSET:
            elt = hta_find_req_header(r, &hd->name);
            while (elt != NULL) {
                elt->hash = 0;
                elt->value.len = 0;
                elt = hta_find_req_header(r, &hd->name);
            }
            hta_repoint_indexed(r, &hd->name, NULL);
            break;

        case HTA_HDR_SET:
            /* drop all existing copies, then add fresh */
            elt = hta_find_req_header(r, &hd->name);
            while (elt != NULL) {
                elt->hash = 0;
                elt->value.len = 0;
                elt = hta_find_req_header(r, &hd->name);
            }
            /* FALLTHROUGH */
            /* fall through */
        case HTA_HDR_ADD:
        case HTA_HDR_APPEND:
            elt = ngx_list_push(&r->headers_in.headers);
            if (elt == NULL) return;
            ngx_memzero(elt, sizeof(ngx_table_elt_t));
            elt->key   = hd->name;
            elt->value = hv;
            elt->hash  = 1;
            /* nginx hashes lowercase header names for indexed lookups */
            elt->lowcase_key = ngx_pnalloc(r->pool, hd->name.len);
            if (elt->lowcase_key) {
                ngx_uint_t k;
                for (k = 0; k < hd->name.len; k++)
                    elt->lowcase_key[k] = ngx_tolower(hd->name.data[k]);
            }
            hta_repoint_indexed(r, &hd->name, elt);
            break;

        case HTA_HDR_MERGE: {
            /* merge: if entry exists and already contains value, skip; else
             * append a fresh entry like APPEND */
            ngx_table_elt_t *existing = hta_find_req_header(r, &hd->name);
            if (existing
                && hv.len > 0
                && existing->value.len >= hv.len
                && ngx_strnstr(existing->value.data,
                       (char *)hv.data, existing->value.len) != NULL)
            {
                break;
            }
            elt = ngx_list_push(&r->headers_in.headers);
            if (elt == NULL) return;
            ngx_memzero(elt, sizeof(ngx_table_elt_t));
            elt->key   = hd->name;
            elt->value = hv;
            elt->hash  = 1;
            elt->lowcase_key = ngx_pnalloc(r->pool, hd->name.len);
            if (elt->lowcase_key) {
                ngx_uint_t k;
                for (k = 0; k < hd->name.len; k++)
                    elt->lowcase_key[k] = ngx_tolower(hd->name.data[k]);
            }
            hta_repoint_indexed(r, &hd->name, elt);
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
