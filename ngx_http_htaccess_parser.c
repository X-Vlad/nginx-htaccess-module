/*
 * ngx_http_htaccess_parser.c - .htaccess file parsing
 *
 * Tokenizer, directive parsers, file reader with line continuation.
 * Supports block tags (<IfModule>, <Files>, <FilesMatch>) with nesting.
 */

#include "ngx_http_htaccess_module.h"


/* ═══════════════════════════════════════════════════════════════════════════
 * Strip CR/LF from a string in-place - prevents HTTP response splitting
 * ═══════════════════════════════════════════════════════════════════════ */

static void
hta_strip_crlf(u_char *s, size_t *len)
{
    u_char *r = s, *w = s, *end = s + *len;
    while (r < end) {
        if (*r != '\r' && *r != '\n') *w++ = *r;
        r++;
    }
    *w = '\0';
    *len = w - s;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Tokenizer - split line into args, respecting quotes
 * ═══════════════════════════════════════════════════════════════════════ */

ngx_uint_t
hta_tokenize(u_char *line, ngx_uint_t len, u_char **args, ngx_uint_t maxargs)
{
    u_char *p = line, *end = line + len;
    ngx_uint_t n = 0;

    while (p < end && n < maxargs) {
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        if (p >= end) break;

        if (*p == '"' || *p == '\'') {
            u_char q = *p++;
            args[n++] = p;
            while (p < end && *p != q) {
                if (*p == '\\' && p + 1 < end) {
                    ngx_memmove(p, p + 1, end - p - 1);
                    end--; len--;
                }
                p++;
            }
            if (p < end) *p++ = '\0';
        } else {
            args[n++] = p;
            while (p < end && *p != ' ' && *p != '\t') p++;
            if (p < end) *p++ = '\0';
        }
    }
    return n;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Rewrite flag parser - [L,R=301,NC,QSA,...]
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_uint_t
hta_parse_flags(u_char *str, ngx_int_t *rcode, ngx_int_t *skip,
    ngx_str_t *ekey, ngx_str_t *eval)
{
    u_char *p, *end, *s;
    ngx_uint_t f = 0;

    *rcode = 302;
    *skip = 0;

    if (str == NULL) return 0;

    p = str;
    if (*p == '[') p++;
    end = p + ngx_strlen(p);
    if (end > p && *(end - 1) == ']') { end--; *end = '\0'; }

    while (p < end) {
        while (p < end && (*p == ' ' || *p == ',' || *p == '\t')) p++;
        if (p >= end) break;
        s = p;
        while (p < end && *p != ',' && *p != ' ') p++;
        if (p < end) *p++ = '\0';

        if (ngx_strcasecmp(s, (u_char *)"L") == 0)        f |= HTA_F_LAST;
        else if (ngx_strcasecmp(s, (u_char *)"END") == 0)  f |= HTA_F_END;
        else if (ngx_strcasecmp(s, (u_char *)"R") == 0)    { f |= HTA_F_REDIRECT; *rcode = 302; }
        else if (ngx_strncasecmp(s, (u_char *)"R=", 2) == 0) {
            f |= HTA_F_REDIRECT;
            *rcode = ngx_atoi(s + 2, ngx_strlen(s + 2));
            if (*rcode < 300 || *rcode > 399) *rcode = 302;
        }
        else if (ngx_strcasecmp(s, (u_char *)"F") == 0)    f |= HTA_F_FORBIDDEN;
        else if (ngx_strcasecmp(s, (u_char *)"G") == 0)    f |= HTA_F_GONE;
        else if (ngx_strcasecmp(s, (u_char *)"NC") == 0)   f |= HTA_F_NOCASE;
        else if (ngx_strcasecmp(s, (u_char *)"NE") == 0)   f |= HTA_F_NOESCAPE;
        else if (ngx_strcasecmp(s, (u_char *)"QSA") == 0)  f |= HTA_F_QSA;
        else if (ngx_strcasecmp(s, (u_char *)"QSD") == 0)  f |= HTA_F_QSD;
        else if (ngx_strcasecmp(s, (u_char *)"PT") == 0)   f |= HTA_F_PT;
        else if (ngx_strcasecmp(s, (u_char *)"C") == 0)    f |= HTA_F_CHAIN;
        else if (ngx_strncasecmp(s, (u_char *)"S=", 2) == 0) {
            f |= HTA_F_SKIP;
            *skip = ngx_atoi(s + 2, ngx_strlen(s + 2));
        }
        else if (ngx_strncasecmp(s, (u_char *)"E=", 2) == 0) {
            f |= HTA_F_ENV;
            u_char *colon = (u_char *)ngx_strchr(s + 2, ':');
            if (colon) {
                ekey->data = s + 2; ekey->len = colon - (s + 2);
                eval->data = colon + 1; eval->len = ngx_strlen(colon + 1);
            }
        }
    }
    return f;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * RewriteCond parser
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_parse_cond(hta_parsed_t *h, u_char **args, ngx_uint_t n, ngx_log_t *log)
{
    hta_cond_t         *c;
    u_char             *pat;
    ngx_uint_t          fl = 0;
    ngx_regex_compile_t rc;
    u_char              errbuf[256];

    if (n < 3 || h->npending >= HTA_MAX_CONDS) return NGX_ERROR;

    c = &h->pending_conds[h->npending];
    ngx_memzero(c, sizeof(hta_cond_t));

    c->test_string.data = args[1];
    c->test_string.len  = ngx_strlen(args[1]);

    pat = args[2];

    /* flags */
    if (n >= 4 && args[3][0] == '[') {
        if (ngx_strstr(args[3], "NC") || ngx_strstr(args[3], "nc") ||
            ngx_strstr(args[3], "nocase"))
            fl |= HTA_CF_NOCASE;
        if (ngx_strstr(args[3], "OR") || ngx_strstr(args[3], "or") ||
            ngx_strstr(args[3], "ornext"))
            fl |= HTA_CF_OR;
    }

    /* negation */
    if (pat[0] == '!') { fl |= HTA_CF_NEGATE; pat++; }

    /* test type */
    if      (ngx_strcmp(pat, "-f") == 0) c->test_type = HTA_TEST_FILE;
    else if (ngx_strcmp(pat, "-d") == 0) c->test_type = HTA_TEST_DIR;
    else if (ngx_strcmp(pat, "-l") == 0) c->test_type = HTA_TEST_LINK;
    else if (ngx_strcmp(pat, "-e") == 0) c->test_type = HTA_TEST_EXISTS;
    else if (ngx_strcmp(pat, "-s") == 0) c->test_type = HTA_TEST_SIZE;
    else {
        c->test_type = HTA_TEST_REGEX;
        c->cond_pattern.data = pat;
        c->cond_pattern.len  = ngx_strlen(pat);

        ngx_memzero(&rc, sizeof(rc));
        rc.pattern = c->cond_pattern;
        rc.pool = h->pool;
        rc.err.data = errbuf;
        rc.err.len = sizeof(errbuf);
        if (fl & HTA_CF_NOCASE) rc.options = NGX_REGEX_CASELESS;

        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "htaccess: bad RewriteCond pattern \"%s\": %V", pat, &rc.err);
            return NGX_ERROR;
        }
        c->regex = rc.regex;
    }

    c->flags = fl;
    h->npending++;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * RewriteRule parser
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_parse_rule(hta_parsed_t *h, u_char **args, ngx_uint_t n, ngx_log_t *log)
{
    hta_rule_t         *rule;
    ngx_uint_t          i;
    ngx_regex_compile_t rc;
    u_char              errbuf[256];

    if (n < 3 || h->nrules >= HTA_MAX_RULES) return NGX_ERROR;

    rule = &h->rules[h->nrules];
    ngx_memzero(rule, sizeof(hta_rule_t));

    rule->pattern.data = args[1];
    rule->pattern.len  = ngx_strlen(args[1]);
    rule->substitution.data = args[2];
    rule->substitution.len  = ngx_strlen(args[2]);

    if (n >= 4) {
        rule->flags = hta_parse_flags(args[3], &rule->redirect_code,
                                       &rule->skip_count,
                                       &rule->env_key, &rule->env_val);
    }

    /* compile regex */
    ngx_memzero(&rc, sizeof(rc));
    rc.pattern = rule->pattern;
    rc.pool = h->pool;
    rc.err.data = errbuf;
    rc.err.len = sizeof(errbuf);
    if (rule->flags & HTA_F_NOCASE) rc.options = NGX_REGEX_CASELESS;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "htaccess: bad RewriteRule pattern \"%V\": %V",
            &rule->pattern, &rc.err);
        return NGX_ERROR;
    }
    rule->regex = rc.regex;

    /* attach pending conditions - allocate exactly what's needed */
    if (h->npending > 0) {
        rule->conds = ngx_palloc(h->pool,
                                  sizeof(hta_cond_t) * h->npending);
        if (rule->conds == NULL) return NGX_ERROR;
        rule->nconds = h->npending;
        for (i = 0; i < h->npending; i++)
            rule->conds[i] = h->pending_conds[i];
    }
    h->npending = 0;

    h->nrules++;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Parse Expires duration string - "access plus N seconds/minutes/hours/days/..."
 * Returns seconds or -1 on error
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_parse_expires_duration(u_char *str)
{
    u_char    *p = str;
    ngx_int_t  total = 0;

    /* skip "access" or "modification" keyword */
    if (ngx_strncasecmp(p, (u_char *)"access", 6) == 0) p += 6;
    else if (ngx_strncasecmp(p, (u_char *)"modification", 12) == 0) p += 12;
    else if (ngx_strncasecmp(p, (u_char *)"A", 1) == 0 && !(*p >= '0' && *p <= '9')) p += 1;
    else if (ngx_strncasecmp(p, (u_char *)"M", 1) == 0 && !(*p >= '0' && *p <= '9')) p += 1;

    /* skip optional "plus" keyword */
    while (*p == ' ') p++;
    if (ngx_strncasecmp(p, (u_char *)"plus", 4) == 0) p += 4;

    while (*p) {
        ngx_int_t num;

        while (*p == ' ' || *p == '+') p++;
        if (*p == '\0') break;

        num = 0;
        while (*p >= '0' && *p <= '9') {
            num = num * 10 + (*p - '0');
            p++;
        }
        while (*p == ' ') p++;

#define HTA_EXPIRES_MAX (10 * 365 * 24 * 3600)  /* cap at 10 years */

        if (ngx_strncasecmp(p, (u_char *)"year", 4) == 0) {
            if (num <= 10) total += num * 365 * 24 * 3600;
            else total = HTA_EXPIRES_MAX;
            while (*p && *p != ' ' && *p != '+') p++;
        } else if (ngx_strncasecmp(p, (u_char *)"month", 5) == 0) {
            total += num * 30 * 24 * 3600;
            while (*p && *p != ' ' && *p != '+') p++;
        } else if (ngx_strncasecmp(p, (u_char *)"week", 4) == 0) {
            total += num * 7 * 24 * 3600;
            while (*p && *p != ' ' && *p != '+') p++;
        } else if (ngx_strncasecmp(p, (u_char *)"day", 3) == 0) {
            total += num * 24 * 3600;
            while (*p && *p != ' ' && *p != '+') p++;
        } else if (ngx_strncasecmp(p, (u_char *)"hour", 4) == 0) {
            total += num * 3600;
            while (*p && *p != ' ' && *p != '+') p++;
        } else if (ngx_strncasecmp(p, (u_char *)"minute", 6) == 0) {
            total += num * 60;
            while (*p && *p != ' ' && *p != '+') p++;
        } else if (ngx_strncasecmp(p, (u_char *)"second", 6) == 0) {
            total += num;
            while (*p && *p != ' ' && *p != '+') p++;
        } else {
            /* maybe just a number (seconds) */
            total += num;
            break;
        }
        if (total > HTA_EXPIRES_MAX) total = HTA_EXPIRES_MAX;
    }

#undef HTA_EXPIRES_MAX
    return total > 0 ? total : -1;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Line parser - dispatches a single directive line
 * ═══════════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════════════
 * Parse a directive into a <Files>/<FilesMatch> block context
 * Only access control, auth, headers, and type directives are valid here
 * ═══════════════════════════════════════════════════════════════════════ */

static void
hta_parse_line_fb(hta_files_block_t *fb, u_char *line, ngx_uint_t len,
    ngx_pool_t *pool, ngx_log_t *log)
{
    u_char     *args[16];
    ngx_uint_t  n;

    while (len > 0 && (line[0] == ' ' || line[0] == '\t')) { line++; len--; }
    while (len > 0 && (line[len-1] == ' ' || line[len-1] == '\t' ||
                       line[len-1] == '\r' || line[len-1] == '\n'))
    { len--; }
    if (len == 0) return;
    line[len] = '\0';
    if (line[0] == '#') return;
    if (line[0] == '<') return;

    n = hta_tokenize(line, len, args, 16);
    if (n == 0) return;

    /* Order */
    if (ngx_strcasecmp(args[0], (u_char *)"Order") == 0 && n >= 2) {
        fb->has_acl = 1;
        fb->access_order = (ngx_strncasecmp(args[1], (u_char *)"allow", 5) == 0)
                           ? HTA_ORDER_ALLOW_DENY : HTA_ORDER_DENY_ALLOW;
        return;
    }

    /* Allow / Deny */
    if (ngx_strcasecmp(args[0], (u_char *)"Allow") == 0 ||
        ngx_strcasecmp(args[0], (u_char *)"Deny") == 0)
    {
        unsigned   is_allow = (ngx_strcasecmp(args[0], (u_char *)"Allow") == 0);
        ngx_uint_t start = 1;
        ngx_uint_t i;

        fb->has_acl = 1;
        if (n >= 2 && ngx_strcasecmp(args[1], (u_char *)"from") == 0) start = 2;
        for (i = start; i < n && fb->nacl < HTA_MAX_FB_ACL; i++) {
            fb->acl[fb->nacl].value.data = args[i];
            fb->acl[fb->nacl].value.len = ngx_strlen(args[i]);
            fb->acl[fb->nacl].is_allow = is_allow;
            fb->nacl++;
        }
        return;
    }

    /* Require */
    if (ngx_strcasecmp(args[0], (u_char *)"Require") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"all") == 0 && n >= 3) {
            if (ngx_strcasecmp(args[2], (u_char *)"granted") == 0)
                fb->require_granted = 1;
            else if (ngx_strcasecmp(args[2], (u_char *)"denied") == 0)
                fb->require_denied = 1;
        } else if (ngx_strcasecmp(args[1], (u_char *)"valid-user") == 0) {
            fb->auth_valid_user = 1;
        } else if (ngx_strcasecmp(args[1], (u_char *)"user") == 0) {
            ngx_uint_t i;
            for (i = 2; i < n && fb->nauth_users < 8; i++) {
                fb->auth_users[fb->nauth_users].data = args[i];
                fb->auth_users[fb->nauth_users].len = ngx_strlen(args[i]);
                fb->nauth_users++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"ip") == 0 ||
                   ngx_strcasecmp(args[1], (u_char *)"host") == 0) {
            ngx_uint_t i;
            fb->has_acl = 1;
            for (i = 2; i < n && fb->nacl < HTA_MAX_FB_ACL; i++) {
                fb->acl[fb->nacl].value.data = args[i];
                fb->acl[fb->nacl].value.len = ngx_strlen(args[i]);
                fb->acl[fb->nacl].is_allow = 1;
                fb->nacl++;
            }
        }
        return;
    }

    /* Header */
    if (ngx_strcasecmp(args[0], (u_char *)"Header") == 0 && n >= 3) {
        if (fb->nheaders < HTA_MAX_FB_HEADERS) {
            hta_header_t *hd = &fb->headers[fb->nheaders];
            ngx_uint_t    off = 1;
            u_char       *act;

            if (ngx_strcasecmp(args[1], (u_char *)"always") == 0) off = 2;
            if (n <= off + 1) return;
            act = args[off];
            if      (ngx_strcasecmp(act, (u_char *)"set") == 0)    hd->action = HTA_HDR_SET;
            else if (ngx_strcasecmp(act, (u_char *)"unset") == 0)  hd->action = HTA_HDR_UNSET;
            else if (ngx_strcasecmp(act, (u_char *)"append") == 0) hd->action = HTA_HDR_APPEND;
            else if (ngx_strcasecmp(act, (u_char *)"add") == 0)    hd->action = HTA_HDR_ADD;
            else if (ngx_strcasecmp(act, (u_char *)"merge") == 0)  hd->action = HTA_HDR_MERGE;
            else return;
            hd->name.data = args[off + 1];
            hd->name.len = ngx_strlen(args[off + 1]);
            hta_strip_crlf(hd->name.data, &hd->name.len);

            if (hd->action != HTA_HDR_UNSET && n > off + 2) {
                hd->value.data = args[off + 2];
                hd->value.len = ngx_strlen(args[off + 2]);
                hta_strip_crlf(hd->value.data, &hd->value.len);
            }
            fb->nheaders++;
        }
        return;
    }

    /* AuthType */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthType") == 0 && n >= 2) {
        fb->auth_basic = (ngx_strcasecmp(args[1], (u_char *)"Basic") == 0);
        return;
    }
    /* AuthName */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthName") == 0 && n >= 2) {
        fb->auth_name.data = args[1]; fb->auth_name.len = ngx_strlen(args[1]);
        return;
    }
    /* AuthUserFile */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthUserFile") == 0 && n >= 2) {
        fb->auth_user_file.data = args[1];
        fb->auth_user_file.len = ngx_strlen(args[1]);
        return;
    }

    /* ForceType */
    if (ngx_strcasecmp(args[0], (u_char *)"ForceType") == 0 && n >= 2) {
        fb->force_type.data = args[1]; fb->force_type.len = ngx_strlen(args[1]);
        return;
    }

    /* AddType */
    if (ngx_strcasecmp(args[0], (u_char *)"AddType") == 0 && n >= 3) {
        ngx_uint_t     i;
        hta_addtype_t *at;

        for (i = 2; i < n && fb->naddtypes < 8; i++) {
            at = &fb->addtypes[fb->naddtypes];
            at->mime_type.data = args[1];
            at->mime_type.len = ngx_strlen(args[1]);
            at->extension.data = args[i];
            at->extension.len = ngx_strlen(args[i]);
            if (at->extension.len > 0 && at->extension.data[0] == '.') {
                at->extension.data++;
                at->extension.len--;
            }
            fb->naddtypes++;
        }
        return;
    }
}


static void
hta_parse_line(hta_parsed_t *h, u_char *line, ngx_uint_t len, ngx_log_t *log)
{
    u_char     *args[16];
    ngx_uint_t  n;

    /* trim whitespace */
    while (len > 0 && (line[0] == ' ' || line[0] == '\t')) { line++; len--; }
    while (len > 0 && (line[len-1] == ' ' || line[len-1] == '\t' ||
                       line[len-1] == '\r' || line[len-1] == '\n'))
    { len--; }
    if (len == 0) return;
    line[len] = '\0';

    /* skip comments */
    if (line[0] == '#') return;

    /* block close tags - handled by file parser nesting logic */
    if (line[0] == '<' && line[1] == '/') return;

    /* block open tags - handled by file parser nesting logic
     * If we reach here, it means the file parser already decided
     * this line should be processed (e.g., inside an active IfModule block) */
    if (line[0] == '<') return;

    n = hta_tokenize(line, len, args, 16);
    if (n == 0) return;

    /* ---- RewriteEngine ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RewriteEngine") == 0 && n >= 2) {
        h->rewrite_on = (ngx_strcasecmp(args[1], (u_char *)"on") == 0);
        return;
    }

    /* ---- RewriteBase ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RewriteBase") == 0 && n >= 2) {
        h->rewrite_base.data = args[1];
        h->rewrite_base.len = ngx_strlen(args[1]);
        return;
    }

    /* ---- RewriteCond ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RewriteCond") == 0) {
        hta_parse_cond(h, args, n, log);
        return;
    }

    /* ---- RewriteRule ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RewriteRule") == 0) {
        hta_parse_rule(h, args, n, log);
        return;
    }

    /* ---- DirectoryIndex ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"DirectoryIndex") == 0) {
        ngx_uint_t i;
        for (i = 1; i < n && h->nindex < HTA_MAX_INDEX; i++) {
            h->index_files[h->nindex].data = args[i];
            h->index_files[h->nindex].len = ngx_strlen(args[i]);
            h->nindex++;
        }
        return;
    }

    /* ---- ErrorDocument ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"ErrorDocument") == 0 && n >= 3) {
        if (h->nerrdocs < HTA_MAX_ERRDOCS) {
            hta_errdoc_t *ed = &h->errdocs[h->nerrdocs];
            ed->code = ngx_atoi(args[1], ngx_strlen(args[1]));
            ed->response.data = args[2];
            ed->response.len = ngx_strlen(args[2]);
            ed->is_url = (args[2][0] == '/' ||
                          ngx_strncasecmp(args[2], (u_char *)"http", 4) == 0);
            h->nerrdocs++;
        }
        return;
    }

    /* ---- Options ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"Options") == 0) {
        ngx_uint_t i;
        h->has_opts = 1;
        for (i = 1; i < n; i++) {
            u_char *o = args[i];
            unsigned set = 1;
            ngx_uint_t flag = 0;
            if (o[0] == '+') { set = 1; o++; }
            else if (o[0] == '-') { set = 0; o++; }

            if (ngx_strcasecmp(o, (u_char *)"Indexes") == 0) flag = HTA_OPT_INDEXES;
            else if (ngx_strcasecmp(o, (u_char *)"FollowSymLinks") == 0) flag = HTA_OPT_FOLLOWSYM;
            else if (ngx_strcasecmp(o, (u_char *)"SymLinksIfOwnerMatch") == 0) flag = HTA_OPT_FOLLOWSYM;
            else if (ngx_strcasecmp(o, (u_char *)"MultiViews") == 0) flag = HTA_OPT_MULTIVIEWS;
            else if (ngx_strcasecmp(o, (u_char *)"All") == 0) flag = 0xFF;
            else if (ngx_strcasecmp(o, (u_char *)"None") == 0) {
                h->opts_set = 0; h->opts_unset = 0xFF; continue;
            }

            if (set) { h->opts_set |= flag; h->opts_unset &= ~flag; }
            else     { h->opts_unset |= flag; h->opts_set &= ~flag; }
        }
        return;
    }

    /* ---- Order ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"Order") == 0 && n >= 2) {
        h->has_acl = 1;
        h->access_order = (ngx_strncasecmp(args[1], (u_char *)"allow", 5) == 0)
                          ? HTA_ORDER_ALLOW_DENY : HTA_ORDER_DENY_ALLOW;
        return;
    }

    /* ---- Allow / Deny ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"Allow") == 0 ||
        ngx_strcasecmp(args[0], (u_char *)"Deny") == 0)
    {
        unsigned   is_allow = (ngx_strcasecmp(args[0], (u_char *)"Allow") == 0);
        ngx_uint_t start = 1;
        ngx_uint_t i;

        h->has_acl = 1;
        if (n >= 2 && ngx_strcasecmp(args[1], (u_char *)"from") == 0) start = 2;
        for (i = start; i < n && h->nacl < HTA_MAX_USERS; i++) {
            h->acl[h->nacl].value.data = args[i];
            h->acl[h->nacl].value.len = ngx_strlen(args[i]);
            h->acl[h->nacl].is_allow = is_allow;
            h->nacl++;
        }
        return;
    }

    /* ---- Require ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"Require") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"all") == 0 && n >= 3) {
            if (ngx_strcasecmp(args[2], (u_char *)"granted") == 0)
                h->require_granted = 1;
            else if (ngx_strcasecmp(args[2], (u_char *)"denied") == 0)
                h->require_denied = 1;
        } else if (ngx_strcasecmp(args[1], (u_char *)"valid-user") == 0) {
            h->auth_valid_user = 1;
        } else if (ngx_strcasecmp(args[1], (u_char *)"user") == 0) {
            ngx_uint_t i;
            for (i = 2; i < n && h->nauth_users < HTA_MAX_USERS; i++) {
                h->auth_users[h->nauth_users].data = args[i];
                h->auth_users[h->nauth_users].len = ngx_strlen(args[i]);
                h->nauth_users++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"ip") == 0 ||
                   ngx_strcasecmp(args[1], (u_char *)"host") == 0) {
            ngx_uint_t i;
            h->has_acl = 1;
            for (i = 2; i < n && h->nacl < HTA_MAX_USERS; i++) {
                h->acl[h->nacl].value.data = args[i];
                h->acl[h->nacl].value.len = ngx_strlen(args[i]);
                h->acl[h->nacl].is_allow = 1;
                h->nacl++;
            }
        }
        return;
    }

    /* ---- Header ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"Header") == 0 && n >= 3) {
        if (h->nheaders < HTA_MAX_HEADERS) {
            hta_header_t *hd = &h->headers[h->nheaders];
            ngx_uint_t    off = 1;
            u_char       *act;

            if (ngx_strcasecmp(args[1], (u_char *)"always") == 0) off = 2;
            if (n <= off + 1) return;

            act = args[off];
            if      (ngx_strcasecmp(act, (u_char *)"set") == 0)    hd->action = HTA_HDR_SET;
            else if (ngx_strcasecmp(act, (u_char *)"unset") == 0)  hd->action = HTA_HDR_UNSET;
            else if (ngx_strcasecmp(act, (u_char *)"append") == 0) hd->action = HTA_HDR_APPEND;
            else if (ngx_strcasecmp(act, (u_char *)"add") == 0)    hd->action = HTA_HDR_ADD;
            else if (ngx_strcasecmp(act, (u_char *)"merge") == 0)  hd->action = HTA_HDR_MERGE;
            else return;

            hd->name.data = args[off + 1];
            hd->name.len = ngx_strlen(args[off + 1]);
            hta_strip_crlf(hd->name.data, &hd->name.len);

            if (hd->action != HTA_HDR_UNSET && n > off + 2) {
                hd->value.data = args[off + 2];
                hd->value.len = ngx_strlen(args[off + 2]);
                hta_strip_crlf(hd->value.data, &hd->value.len);
            }
            h->nheaders++;
        }
        return;
    }

    /* ---- AuthType ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthType") == 0 && n >= 2) {
        h->auth_basic = (ngx_strcasecmp(args[1], (u_char *)"Basic") == 0);
        return;
    }

    /* ---- AuthName ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthName") == 0 && n >= 2) {
        h->auth_name.data = args[1]; h->auth_name.len = ngx_strlen(args[1]);
        return;
    }

    /* ---- AuthUserFile ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthUserFile") == 0 && n >= 2) {
        h->auth_user_file.data = args[1];
        h->auth_user_file.len = ngx_strlen(args[1]);
        return;
    }

    /* ---- ForceType ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"ForceType") == 0 && n >= 2) {
        h->force_type.data = args[1]; h->force_type.len = ngx_strlen(args[1]);
        return;
    }

    /* ---- DefaultType ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"DefaultType") == 0 && n >= 2) {
        h->default_type.data = args[1]; h->default_type.len = ngx_strlen(args[1]);
        return;
    }

    /* ---- AddType ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AddType") == 0 && n >= 3) {
        ngx_uint_t i;
        for (i = 2; i < n && h->naddtypes < HTA_MAX_ADDTYPES; i++) {
            hta_addtype_t *at = &h->addtypes[h->naddtypes];
            at->mime_type.data = args[1];
            at->mime_type.len = ngx_strlen(args[1]);
            at->extension.data = args[i];
            at->extension.len = ngx_strlen(args[i]);
            /* strip leading dot if present */
            if (at->extension.len > 0 && at->extension.data[0] == '.') {
                at->extension.data++;
                at->extension.len--;
            }
            h->naddtypes++;
        }
        return;
    }

    /* ---- ExpiresActive ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"ExpiresActive") == 0 && n >= 2) {
        h->expires_active = (ngx_strcasecmp(args[1], (u_char *)"on") == 0);
        return;
    }

    /* ---- ExpiresDefault ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"ExpiresDefault") == 0 && n >= 2) {
        h->expires_default = hta_parse_expires_duration(args[1]);
        return;
    }

    /* ---- ExpiresByType ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"ExpiresByType") == 0 && n >= 3) {
        if (h->nexpires < HTA_MAX_EXPIRES) {
            hta_expires_t *ex = &h->expires[h->nexpires];
            ex->mime_type.data = args[1];
            ex->mime_type.len = ngx_strlen(args[1]);
            ex->seconds = hta_parse_expires_duration(args[2]);
            if (ex->seconds > 0) h->nexpires++;
        }
        return;
    }

    /* ---- SetEnvIf ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"SetEnvIf") == 0 && n >= 4) {
        if (h->nsetenvifs < HTA_MAX_SETENVIF) {
            hta_setenvif_t     *se = &h->setenvifs[h->nsetenvifs];
            ngx_regex_compile_t rc;
            u_char              errbuf[256];
            u_char             *eq;

            se->attribute.data = args[1];
            se->attribute.len = ngx_strlen(args[1]);
            se->pattern.data = args[2];
            se->pattern.len = ngx_strlen(args[2]);

            /* compile regex */
            ngx_memzero(&rc, sizeof(rc));
            rc.pattern = se->pattern;
            rc.pool = h->pool;
            rc.err.data = errbuf;
            rc.err.len = sizeof(errbuf);
            if (ngx_regex_compile(&rc) == NGX_OK) {
                se->regex = rc.regex;
            } else {
                se->regex = NULL;
            }

            /* parse env=val or just env */
            eq = (u_char *)ngx_strchr(args[3], '=');
            if (eq) {
                se->env_name.data = args[3];
                se->env_name.len = eq - args[3];
                se->env_value.data = eq + 1;
                se->env_value.len = ngx_strlen(eq + 1);
            } else {
                se->env_name.data = args[3];
                se->env_name.len = ngx_strlen(args[3]);
                ngx_str_set(&se->env_value, "1");
            }
            h->nsetenvifs++;
        }
        return;
    }

    /* ---- Redirect ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"Redirect") == 0 && n >= 2) {
        if (h->nredirects < HTA_MAX_REDIRECTS) {
            hta_redirect_t *rd = &h->redirects[h->nredirects];
            ngx_uint_t      arg_off = 1;

            ngx_memzero(rd, sizeof(hta_redirect_t));
            rd->is_match = 0;

            /* Redirect [status] source target */
            if (n >= 3 && args[1][0] >= '0' && args[1][0] <= '9') {
                rd->status = ngx_atoi(args[1], ngx_strlen(args[1]));
                arg_off = 2;
            } else if (n >= 3 && ngx_strcasecmp(args[1], (u_char *)"permanent") == 0) {
                rd->status = 301;
                arg_off = 2;
            } else if (n >= 3 && ngx_strcasecmp(args[1], (u_char *)"temp") == 0) {
                rd->status = 302;
                arg_off = 2;
            } else if (n >= 3 && ngx_strcasecmp(args[1], (u_char *)"seeother") == 0) {
                rd->status = 303;
                arg_off = 2;
            } else if (n >= 3 && ngx_strcasecmp(args[1], (u_char *)"gone") == 0) {
                rd->status = 410;
                arg_off = 2;
            } else {
                rd->status = 302;
            }

            if (arg_off < n) {
                rd->source.data = args[arg_off];
                rd->source.len = ngx_strlen(args[arg_off]);
            }
            if (arg_off + 1 < n && rd->status != 410) {
                rd->target.data = args[arg_off + 1];
                rd->target.len = ngx_strlen(args[arg_off + 1]);
            }
            h->nredirects++;
        }
        return;
    }

    /* ---- RedirectPermanent ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RedirectPermanent") == 0 && n >= 3) {
        if (h->nredirects < HTA_MAX_REDIRECTS) {
            hta_redirect_t *rd = &h->redirects[h->nredirects];
            ngx_memzero(rd, sizeof(hta_redirect_t));
            rd->status = 301;
            rd->source.data = args[1]; rd->source.len = ngx_strlen(args[1]);
            rd->target.data = args[2]; rd->target.len = ngx_strlen(args[2]);
            h->nredirects++;
        }
        return;
    }

    /* ---- RedirectTemp ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RedirectTemp") == 0 && n >= 3) {
        if (h->nredirects < HTA_MAX_REDIRECTS) {
            hta_redirect_t *rd = &h->redirects[h->nredirects];
            ngx_memzero(rd, sizeof(hta_redirect_t));
            rd->status = 302;
            rd->source.data = args[1]; rd->source.len = ngx_strlen(args[1]);
            rd->target.data = args[2]; rd->target.len = ngx_strlen(args[2]);
            h->nredirects++;
        }
        return;
    }

    /* ---- RedirectMatch ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RedirectMatch") == 0 && n >= 2) {
        if (h->nredirects < HTA_MAX_REDIRECTS) {
            hta_redirect_t *rd = &h->redirects[h->nredirects];
            ngx_uint_t      arg_off = 1;

            ngx_memzero(rd, sizeof(hta_redirect_t));
            rd->is_match = 1;

            /* RedirectMatch [status] pattern target */
            if (n >= 3 && args[1][0] >= '0' && args[1][0] <= '9') {
                rd->status = ngx_atoi(args[1], ngx_strlen(args[1]));
                arg_off = 2;
            } else if (n >= 3 && ngx_strcasecmp(args[1], (u_char *)"permanent") == 0) {
                rd->status = 301; arg_off = 2;
            } else if (n >= 3 && ngx_strcasecmp(args[1], (u_char *)"temp") == 0) {
                rd->status = 302; arg_off = 2;
            } else {
                rd->status = 302;
            }

            if (arg_off < n) {
                ngx_regex_compile_t rc;
                u_char              errbuf[256];

                rd->source.data = args[arg_off];
                rd->source.len = ngx_strlen(args[arg_off]);

                /* compile regex */
                ngx_memzero(&rc, sizeof(rc));
                rc.pattern = rd->source;
                rc.pool = h->pool;
                rc.err.data = errbuf;
                rc.err.len = sizeof(errbuf);
                if (ngx_regex_compile(&rc) == NGX_OK) {
                    rd->regex = rc.regex;
                } else {
                    ngx_log_error(NGX_LOG_WARN, log, 0,
                        "htaccess: bad RedirectMatch pattern \"%V\": %V",
                        &rd->source, &rc.err);
                    return;
                }
            }
            if (arg_off + 1 < n) {
                rd->target.data = args[arg_off + 1];
                rd->target.len = ngx_strlen(args[arg_off + 1]);
            }
            h->nredirects++;
        }
        return;
    }

    /* ---- php_value / php_admin_value / php_flag - ignore with debug log ---- */
    if (ngx_strncasecmp(args[0], (u_char *)"php_", 4) == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "htaccess: ignoring PHP directive \"%s\"", args[0]);
        return;
    }

    /* ---- AddHandler - ignore with debug log ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AddHandler") == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0,
            "htaccess: ignoring AddHandler (use FPM config)");
        return;
    }

    /* ---- AddCharset - ignore ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AddCharset") == 0) return;

    /* ---- Satisfy - ignore (deprecated in Apache 2.4) ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"Satisfy") == 0) return;

    /* ---- SetHandler - ignore ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"SetHandler") == 0) return;

    /* ---- AddDefaultCharset ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AddDefaultCharset") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"Off") != 0) {
            h->default_charset.data = args[1];
            h->default_charset.len = ngx_strlen(args[1]);
        }
        return;
    }

    /* ---- RewriteMap - not supported, warn ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"RewriteMap") == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "htaccess: RewriteMap is not supported");
        return;
    }

    /* ---- Gracefully ignored directives ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"SetInputFilter") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SetOutputFilter") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"AddOutputFilterByType") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"RemoveHandler") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"RemoveType") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"ServerSignature") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"FileETag") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"LimitRequestBody") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"AddEncoding") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"AddLanguage") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"LanguagePriority") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"ForceLanguagePriority") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"AddInputFilter") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"AddOutputFilter") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"BrowserMatch") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"BrowserMatchNoCase") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SSLOptions") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SSLRequireSSL") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SSLRequire") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"Action") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SetEnvIfNoCase") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"PassEnv") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"UnsetEnv") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"RequestHeader") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecFilterEngine") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecFilterScanPOST") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecRule") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecAction") == 0) return;

    /* Unknown directives silently ignored */
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Check if a block tag line is a known block we handle
 * Returns 1 if block should be entered (content processed), 0 if skipped
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_should_enter_block(u_char *line, ngx_uint_t len)
{
    /* <IfModule ...> - always enter (we emulate having all modules) */
    if (len >= 10 && ngx_strncasecmp(line + 1, (u_char *)"IfModule", 8) == 0) {
        /* Check for negation: <IfModule !mod_xxx> */
        u_char *p = line + 9;
        u_char *pend = line + len;
        while (p < pend && (*p == ' ' || *p == '\t')) p++;
        if (p < pend && *p == '!') {
            /* Negated: module NOT present - skip this block */
            return 0;
        }
        return 1;
    }

    /* <ElseIf ...>, <Else> - skip (Apache expression blocks) */
    if (len >= 6 && ngx_strncasecmp(line + 1, (u_char *)"Else", 4) == 0) {
        return 0;
    }

    /* <If ...> - we cannot evaluate arbitrary Apache expressions, skip */
    if (len > 3 && ngx_strncasecmp(line + 1, (u_char *)"If ", 3) == 0) {
        return 0;
    }
    if (len > 4 && ngx_strncasecmp(line + 1, (u_char *)"If>", 3) == 0) {
        return 0;
    }

    /* <Directory ...>, <Location ...> - skip (not per-dir context) */
    if (len >= 11 && ngx_strncasecmp(line + 1, (u_char *)"Directory", 9) == 0) return 0;
    if (len >= 10 && ngx_strncasecmp(line + 1, (u_char *)"Location", 8) == 0) return 0;

    /* <Files ...>, <FilesMatch ...> - enter (apply to matching files) */
    if (len >= 7 && ngx_strncasecmp(line + 1, (u_char *)"Files", 5) == 0) return 1;

    /* <Limit ...>, <LimitExcept ...> - enter (we apply all methods) */
    if (len >= 7 && ngx_strncasecmp(line + 1, (u_char *)"Limit", 5) == 0) return 1;

    /* <RequireAll>, <RequireAny>, <RequireNone> - enter (simplified) */
    if (len >= 12 && ngx_strncasecmp(line + 1, (u_char *)"Require", 7) == 0) return 1;

    /* Unknown blocks - skip */
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * File parser - reads .htaccess file and parses all directives
 * Handles line continuation (\), block nesting, comments
 * ═══════════════════════════════════════════════════════════════════════ */

hta_parsed_t *
hta_parse_file(ngx_pool_t *pool, u_char *filepath, ngx_log_t *log)
{
    hta_parsed_t      *h;
    ngx_fd_t           fd;
    ngx_file_info_t    fi;
    u_char            *buf, *p, *end, *ls;
    ssize_t            nr;
    off_t              sz;
    u_char             line_buf[HTA_MAX_LINE];
    ngx_uint_t         lb_len;
    unsigned           cont;
    ngx_int_t          skip_depth;
    hta_files_block_t *cur_fb;
    ngx_int_t          files_depth;

    fd = ngx_open_file(filepath, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) return NULL;

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) { ngx_close_file(fd); return NULL; }
    sz = ngx_file_size(&fi);
    if (sz == 0 || sz > 1024 * 1024) { ngx_close_file(fd); return NULL; }

    h = ngx_pcalloc(pool, sizeof(hta_parsed_t));
    if (h == NULL) { ngx_close_file(fd); return NULL; }
    h->pool = pool;
    h->mtime = ngx_file_mtime(&fi);
    h->expires_default = -1;

    buf = ngx_palloc(pool, sz + 1);
    if (buf == NULL) { ngx_close_file(fd); return NULL; }

    nr = ngx_read_fd(fd, buf, sz);
    ngx_close_file(fd);
    if (nr <= 0) return NULL;
    buf[nr] = '\0';

    /* parse line by line with continuation and block nesting support */
    lb_len = 0;
    cont = 0;
    skip_depth = 0;   /* >0 means we're inside a skipped block */
    cur_fb = NULL;     /* non-NULL = inside <Files> block */
    files_depth = 0;   /* nesting depth within Files block */

    p = buf;
    end = buf + nr;
    ls = p;

    while (p <= end) {
        if (p == end || *p == '\n') {
            ngx_uint_t  seg;
            u_char     *parse_line;
            ngx_uint_t  parse_len;

            seg = p - ls;
            if (seg > 0 && ls[seg - 1] == '\r') seg--;

            if (seg > 0 && ls[seg - 1] == '\\') {
                seg--;
                if (lb_len + seg < HTA_MAX_LINE - 1) {
                    ngx_memcpy(line_buf + lb_len, ls, seg);
                    lb_len += seg;
                }
                cont = 1;
            } else {
                if (cont) {
                    if (lb_len + seg < HTA_MAX_LINE - 1) {
                        ngx_memcpy(line_buf + lb_len, ls, seg);
                        lb_len += seg;
                    }
                    line_buf[lb_len] = '\0';
                    parse_line = line_buf;
                    parse_len = lb_len;
                } else if (seg > 0) {
                    parse_line = ls;
                    parse_len = seg;
                } else {
                    parse_line = NULL;
                    parse_len = 0;
                }

                if (parse_line && parse_len > 0) {
                    /* make a writable copy in pool */
                    u_char *wl = ngx_pnalloc(pool, parse_len + 1);
                    if (wl) {
                        /* trim whitespace for block detection */
                        u_char    *trimmed;
                        ngx_uint_t tlen;

                        ngx_memcpy(wl, parse_line, parse_len);
                        wl[parse_len] = '\0';

                        trimmed = wl;
                        tlen = parse_len;
                        while (tlen > 0 && (*trimmed == ' ' || *trimmed == '\t')) {
                            trimmed++; tlen--;
                        }
                        while (tlen > 0 && (trimmed[tlen-1] == ' ' ||
                               trimmed[tlen-1] == '\t' || trimmed[tlen-1] == '\r'))
                        { tlen--; }

                        if (tlen > 0 && trimmed[0] == '#') {
                            /* comment - skip */
                        } else if (tlen > 2 && trimmed[0] == '<'
                                   && trimmed[1] == '/') {
                            /* closing block tag */
                            if (skip_depth > 0) {
                                skip_depth--;
                            } else if (cur_fb) {
                                /* closing a <Files>/<FilesMatch> block */
                                if (files_depth > 0) {
                                    files_depth--;
                                } else {
                                    cur_fb = NULL;
                                }
                            }
                        } else if (tlen > 1 && trimmed[0] == '<'
                                   && trimmed[tlen-1] == '>') {
                            /* opening block tag */
                            if (skip_depth > 0) {
                                skip_depth++;
                            } else if (cur_fb) {
                                /* nested block inside <Files> */
                                if (hta_should_enter_block(trimmed, tlen)) {
                                    files_depth++;
                                } else {
                                    skip_depth = 1;
                                }
                            } else if (ngx_strncasecmp(trimmed + 1,
                                           (u_char *)"Files", 5) == 0
                                       && h->nfiles_blocks
                                              < HTA_MAX_FILES_BLOCKS)
                            {
                                /* entering <Files> or <FilesMatch> block */
                                hta_files_block_t *fb =
                                    &h->files_blocks[h->nfiles_blocks];
                                u_char *ps;
                                u_char *pe;

                                ngx_memzero(fb, sizeof(hta_files_block_t));

                                fb->is_regex = (ngx_strncasecmp(trimmed + 1,
                                    (u_char *)"FilesMatch", 10) == 0);

                                /* extract pattern from tag:
                                 * <Files "pattern"> or <FilesMatch "regex">
                                 */
                                ps = trimmed + (fb->is_regex ? 12 : 7);
                                while (*ps == ' ' || *ps == '\t') ps++;
                                if (*ps == '"' || *ps == '\'') ps++;
                                pe = trimmed + tlen - 1; /* before > */
                                while (pe > ps && (*(pe-1) == '"'
                                       || *(pe-1) == '\'' || *(pe-1) == ' '))
                                    pe--;
                                fb->pattern.data = ps;
                                fb->pattern.len = pe - ps;

                                if (fb->is_regex && fb->pattern.len > 0) {
                                    ngx_regex_compile_t rc;
                                    u_char errbuf[256];
                                    ngx_memzero(&rc, sizeof(rc));
                                    rc.pattern = fb->pattern;
                                    rc.pool = pool;
                                    rc.err.data = errbuf;
                                    rc.err.len = sizeof(errbuf);
                                    if (ngx_regex_compile(&rc) == NGX_OK) {
                                        fb->regex = rc.regex;
                                    } else {
                                        ngx_log_error(NGX_LOG_WARN, log, 0,
                                            "htaccess: bad FilesMatch "
                                            "pattern \"%V\": %V",
                                            &fb->pattern, &rc.err);
                                    }
                                }

                                cur_fb = fb;
                                h->nfiles_blocks++;
                            } else if (!hta_should_enter_block(
                                           trimmed, tlen)) {
                                skip_depth = 1;
                            }
                            /* if entering a non-Files block, skip tag line */
                        } else if (skip_depth == 0) {
                            if (cur_fb) {
                                hta_parse_line_fb(cur_fb, wl, parse_len,
                                                  pool, log);
                            } else {
                                hta_parse_line(h, wl, parse_len, log);
                            }
                        }
                    }
                }

                lb_len = 0;
                cont = 0;
            }
            if (p < end) ls = p + 1;
        }
        p++;
    }

    return h;
}
