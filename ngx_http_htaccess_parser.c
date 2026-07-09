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


/* Case-insensitive test: does a token contain the substring "php"? Used to
 * recognize RemoveHandler/AddType tokens that concern PHP execution. */
static ngx_int_t
hta_token_has_php(u_char *s)
{
    for (; *s; s++) {
        if ((s[0] == 'p' || s[0] == 'P')
            && (s[1] == 'h' || s[1] == 'H')
            && (s[2] == 'p' || s[2] == 'P'))
            return 1;
    }
    return 0;
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
            /* Apache allows any status with R=. 3xx are redirects; 4xx/5xx make
             * the rule respond with that error status (e.g. the common
             * "- [R=404]" file-hiding idiom). Only a truly invalid code falls
             * back to 302. */
            if (*rcode < 100 || *rcode > 599) *rcode = 302;
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
        /* Apache long-form flag names. Critically, "[forbidden]" must set F -
         * MediaWiki's images/.htaccess uses "RewriteRule . - [forbidden]" to
         * block script execution; matching only the short "F" left it a no-op
         * (served the file = fail-open). */
        else if (ngx_strcasecmp(s, (u_char *)"last") == 0)       f |= HTA_F_LAST;
        else if (ngx_strcasecmp(s, (u_char *)"end") == 0)        f |= HTA_F_END;
        else if (ngx_strcasecmp(s, (u_char *)"forbidden") == 0)  f |= HTA_F_FORBIDDEN;
        else if (ngx_strcasecmp(s, (u_char *)"gone") == 0)       f |= HTA_F_GONE;
        else if (ngx_strcasecmp(s, (u_char *)"nocase") == 0)     f |= HTA_F_NOCASE;
        else if (ngx_strcasecmp(s, (u_char *)"noescape") == 0)   f |= HTA_F_NOESCAPE;
        else if (ngx_strcasecmp(s, (u_char *)"qsappend") == 0)   f |= HTA_F_QSA;
        else if (ngx_strcasecmp(s, (u_char *)"qsdiscard") == 0)  f |= HTA_F_QSD;
        else if (ngx_strcasecmp(s, (u_char *)"passthrough") == 0) f |= HTA_F_PT;
        else if (ngx_strcasecmp(s, (u_char *)"chain") == 0)      f |= HTA_F_CHAIN;
        else if (ngx_strcasecmp(s, (u_char *)"redirect") == 0)   { f |= HTA_F_REDIRECT; *rcode = 302; }
        else if (ngx_strncasecmp(s, (u_char *)"redirect=", 9) == 0) {
            f |= HTA_F_REDIRECT;
            *rcode = ngx_atoi(s + 9, ngx_strlen(s + 9));
            if (*rcode < 100 || *rcode > 599) *rcode = 302;
        }
        else if (ngx_strncasecmp(s, (u_char *)"skip=", 5) == 0) {
            f |= HTA_F_SKIP;
            *skip = ngx_atoi(s + 5, ngx_strlen(s + 5));
        }
        else if (ngx_strncasecmp(s, (u_char *)"env=", 4) == 0) {
            f |= HTA_F_ENV;
            u_char *colon = (u_char *)ngx_strchr(s + 4, ':');
            if (colon) {
                ekey->data = s + 4; ekey->len = colon - (s + 4);
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
    /* lexicographic / integer comparison operators. The operand (right-hand
     * side) is stored in cond_pattern; no regex is compiled. This makes the
     * ubiquitous force-HTTPS idiom "RewriteCond %{HTTPS} !=on" work instead of
     * being misparsed as a never-matching regex. */
    else if (pat[0] == '<' && pat[1] == '=') {
        c->test_type = HTA_TEST_STR_LE;
        c->cond_pattern.data = pat + 2; c->cond_pattern.len = ngx_strlen(pat+2);
    }
    else if (pat[0] == '>' && pat[1] == '=') {
        c->test_type = HTA_TEST_STR_GE;
        c->cond_pattern.data = pat + 2; c->cond_pattern.len = ngx_strlen(pat+2);
    }
    else if (pat[0] == '=') {
        c->test_type = HTA_TEST_STR_EQ;
        c->cond_pattern.data = pat + 1; c->cond_pattern.len = ngx_strlen(pat+1);
    }
    else if (pat[0] == '<') {
        c->test_type = HTA_TEST_STR_LT;
        c->cond_pattern.data = pat + 1; c->cond_pattern.len = ngx_strlen(pat+1);
    }
    else if (pat[0] == '>') {
        c->test_type = HTA_TEST_STR_GT;
        c->cond_pattern.data = pat + 1; c->cond_pattern.len = ngx_strlen(pat+1);
    }
    else if (pat[0] == '-' && (ngx_strncmp(pat+1, "eq", 2) == 0
             || ngx_strncmp(pat+1, "ne", 2) == 0
             || ngx_strncmp(pat+1, "lt", 2) == 0
             || ngx_strncmp(pat+1, "le", 2) == 0
             || ngx_strncmp(pat+1, "gt", 2) == 0
             || ngx_strncmp(pat+1, "ge", 2) == 0)) {
        if      (ngx_strncmp(pat+1,"eq",2)==0) c->test_type = HTA_TEST_INT_EQ;
        else if (ngx_strncmp(pat+1,"ne",2)==0) c->test_type = HTA_TEST_INT_NE;
        else if (ngx_strncmp(pat+1,"lt",2)==0) c->test_type = HTA_TEST_INT_LT;
        else if (ngx_strncmp(pat+1,"le",2)==0) c->test_type = HTA_TEST_INT_LE;
        else if (ngx_strncmp(pat+1,"gt",2)==0) c->test_type = HTA_TEST_INT_GT;
        else                                   c->test_type = HTA_TEST_INT_GE;
        /* operand follows the 3-char operator, optionally after a space */
        {
            u_char *op = pat + 3;
            while (*op == ' ') op++;
            c->cond_pattern.data = op; c->cond_pattern.len = ngx_strlen(op);
        }
    }
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
        } else if (ngx_strcasecmp(args[1], (u_char *)"group") == 0) {
            ngx_uint_t i;
            for (i = 2; i < n && fb->nrequire_groups < 8; i++) {
                fb->require_groups[fb->nrequire_groups].data = args[i];
                fb->require_groups[fb->nrequire_groups].len = ngx_strlen(args[i]);
                fb->nrequire_groups++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"ip") == 0 ||
                   ngx_strcasecmp(args[1], (u_char *)"host") == 0) {
            ngx_uint_t i;
            fb->has_require_host = 1;
            for (i = 2; i < n && fb->nacl < HTA_MAX_FB_ACL; i++) {
                fb->acl[fb->nacl].value.data = args[i];
                fb->acl[fb->nacl].value.len = ngx_strlen(args[i]);
                fb->acl[fb->nacl].is_allow = 1;
                fb->acl[fb->nacl].is_require = 1;
                fb->nacl++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"env") == 0) {
            ngx_uint_t i;
            fb->has_require_host = 1;
            for (i = 2; i < n && fb->nacl < HTA_MAX_FB_ACL; i++) {
                size_t  al = ngx_strlen(args[i]);
                u_char *v  = ngx_pnalloc(pool, 4 + al);
                if (v == NULL) continue;
                ngx_memcpy(v, "env=", 4);
                ngx_memcpy(v + 4, args[i], al);
                fb->acl[fb->nacl].value.data = v;
                fb->acl[fb->nacl].value.len  = 4 + al;
                fb->acl[fb->nacl].is_allow   = 1;
                fb->acl[fb->nacl].is_require = 1;
                fb->nacl++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"local") == 0) {
            fb->require_local = 1;
        } else {
            fb->require_failed = 1;
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "htaccess: unsupported \"Require %s\" in <Files>, "
                "denying block", args[1]);
        }
        return;
    }

    /* AuthGroupFile */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthGroupFile") == 0 && n >= 2) {
        fb->auth_group_file.data = args[1];
        fb->auth_group_file.len = ngx_strlen(args[1]);
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
        if (ngx_strcasecmp(args[1], (u_char *)"Basic") == 0) {
            fb->auth_basic = 1;
            fb->auth_type_unsupported = 0;
        } else {
            fb->auth_basic = 0;
            fb->auth_type_unsupported = 1;
        }
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
    /* AuthGroupFile (Files-block parser also handled at top with Require) */

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

    /* SetHandler none / RemoveHandler .php - upload-dir kill-switch scoped to
     * files matching this block (blocks script execution, see hta_check_exec) */
    if (ngx_strcasecmp(args[0], (u_char *)"SetHandler") == 0) {
        if (n >= 2
            && (ngx_strcasecmp(args[1], (u_char *)"none") == 0
                || ngx_strcasecmp(args[1], (u_char *)"default-handler") == 0))
        {
            fb->exec_disabled = 1;
        }
        return;
    }
    if (ngx_strcasecmp(args[0], (u_char *)"RemoveHandler") == 0) {
        ngx_uint_t i;
        for (i = 1; i < n; i++)
            if (hta_token_has_php(args[i])) { fb->exec_disabled = 1; break; }
        return;
    }
    if (ngx_strncasecmp(args[0], (u_char *)"php_", 4) == 0 && n >= 3
        && ngx_strcasecmp(args[1], (u_char *)"engine") == 0
        && (ngx_strcasecmp(args[2], (u_char *)"off") == 0
            || ngx_strcasecmp(args[2], (u_char *)"0") == 0
            || ngx_strcasecmp(args[2], (u_char *)"false") == 0))
    {
        fb->exec_disabled = 1;
        return;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Parse a directive into a <Limit>/<LimitExcept> block context
 * Only access control + auth directives are meaningful inside Limit
 * ═══════════════════════════════════════════════════════════════════════ */

static void
hta_parse_line_lb(hta_limit_block_t *lb, u_char *line, ngx_uint_t len,
    ngx_pool_t *lb_pool, ngx_log_t *log)
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
        lb->has_acl = 1;
        lb->access_order = (ngx_strncasecmp(args[1], (u_char *)"allow", 5) == 0)
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

        lb->has_acl = 1;
        if (n >= 2 && ngx_strcasecmp(args[1], (u_char *)"from") == 0) start = 2;
        for (i = start; i < n && lb->nacl < HTA_MAX_LB_ACL; i++) {
            lb->acl[lb->nacl].value.data = args[i];
            lb->acl[lb->nacl].value.len = ngx_strlen(args[i]);
            lb->acl[lb->nacl].is_allow = is_allow;
            lb->nacl++;
        }
        return;
    }

    /* Require */
    if (ngx_strcasecmp(args[0], (u_char *)"Require") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"all") == 0 && n >= 3) {
            if (ngx_strcasecmp(args[2], (u_char *)"granted") == 0)
                lb->require_granted = 1;
            else if (ngx_strcasecmp(args[2], (u_char *)"denied") == 0)
                lb->require_denied = 1;
        } else if (ngx_strcasecmp(args[1], (u_char *)"valid-user") == 0) {
            lb->auth_valid_user = 1;
        } else if (ngx_strcasecmp(args[1], (u_char *)"user") == 0) {
            ngx_uint_t i;
            for (i = 2; i < n && lb->nauth_users < 8; i++) {
                lb->auth_users[lb->nauth_users].data = args[i];
                lb->auth_users[lb->nauth_users].len = ngx_strlen(args[i]);
                lb->nauth_users++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"group") == 0) {
            ngx_uint_t i;
            for (i = 2; i < n && lb->nrequire_groups < 8; i++) {
                lb->require_groups[lb->nrequire_groups].data = args[i];
                lb->require_groups[lb->nrequire_groups].len =
                    ngx_strlen(args[i]);
                lb->nrequire_groups++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"ip") == 0 ||
                   ngx_strcasecmp(args[1], (u_char *)"host") == 0) {
            ngx_uint_t i;
            lb->has_require_host = 1;
            for (i = 2; i < n && lb->nacl < HTA_MAX_LB_ACL; i++) {
                lb->acl[lb->nacl].value.data = args[i];
                lb->acl[lb->nacl].value.len = ngx_strlen(args[i]);
                lb->acl[lb->nacl].is_allow = 1;
                lb->acl[lb->nacl].is_require = 1;
                lb->nacl++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"env") == 0) {
            ngx_uint_t i;
            lb->has_require_host = 1;
            for (i = 2; i < n && lb->nacl < HTA_MAX_LB_ACL; i++) {
                size_t  al = ngx_strlen(args[i]);
                u_char *v  = ngx_pnalloc(lb_pool, 4 + al);
                if (v == NULL) continue;
                ngx_memcpy(v, "env=", 4);
                ngx_memcpy(v + 4, args[i], al);
                lb->acl[lb->nacl].value.data = v;
                lb->acl[lb->nacl].value.len  = 4 + al;
                lb->acl[lb->nacl].is_allow   = 1;
                lb->acl[lb->nacl].is_require = 1;
                lb->nacl++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"local") == 0) {
            lb->require_local = 1;
        } else {
            lb->require_failed = 1;
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "htaccess: unsupported \"Require %s\" in <Limit>, "
                "denying block", args[1]);
        }
        return;
    }

    /* AuthType / AuthName / AuthUserFile / AuthGroupFile */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthType") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"Basic") == 0) {
            lb->auth_basic = 1;
            lb->auth_type_unsupported = 0;
        } else {
            lb->auth_basic = 0;
            lb->auth_type_unsupported = 1;
        }
        return;
    }
    if (ngx_strcasecmp(args[0], (u_char *)"AuthName") == 0 && n >= 2) {
        lb->auth_name.data = args[1]; lb->auth_name.len = ngx_strlen(args[1]);
        return;
    }
    if (ngx_strcasecmp(args[0], (u_char *)"AuthUserFile") == 0 && n >= 2) {
        lb->auth_user_file.data = args[1];
        lb->auth_user_file.len = ngx_strlen(args[1]);
        return;
    }
    if (ngx_strcasecmp(args[0], (u_char *)"AuthGroupFile") == 0 && n >= 2) {
        lb->auth_group_file.data = args[1];
        lb->auth_group_file.len = ngx_strlen(args[1]);
        return;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Parse the method list from <Limit METHOD ...> or <LimitExcept METHOD ...>
 * Returns a bitmask of NGX_HTTP_* method constants; 0 = invalid/empty.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_uint_t
hta_parse_methods(u_char *p, u_char *pend)
{
    ngx_uint_t m = 0;

    while (p < pend) {
        u_char    *start;
        ngx_uint_t mlen;

        while (p < pend && (*p == ' ' || *p == '\t' || *p == '"'
                            || *p == '\'')) p++;
        if (p >= pend) break;
        start = p;
        while (p < pend && *p != ' ' && *p != '\t' && *p != '>'
               && *p != '"' && *p != '\'') p++;
        mlen = p - start;
        if (mlen == 0) break;

        if      (mlen == 3 && ngx_strncasecmp(start, (u_char *)"GET", 3) == 0)
            m |= NGX_HTTP_GET;
        else if (mlen == 4 && ngx_strncasecmp(start, (u_char *)"POST", 4) == 0)
            m |= NGX_HTTP_POST;
        else if (mlen == 3 && ngx_strncasecmp(start, (u_char *)"PUT", 3) == 0)
            m |= NGX_HTTP_PUT;
        else if (mlen == 6 && ngx_strncasecmp(start, (u_char *)"DELETE", 6) == 0)
            m |= NGX_HTTP_DELETE;
        else if (mlen == 4 && ngx_strncasecmp(start, (u_char *)"HEAD", 4) == 0)
            m |= NGX_HTTP_HEAD;
        else if (mlen == 7 && ngx_strncasecmp(start, (u_char *)"OPTIONS", 7) == 0)
            m |= NGX_HTTP_OPTIONS;
        else if (mlen == 5 && ngx_strncasecmp(start, (u_char *)"PATCH", 5) == 0)
            m |= NGX_HTTP_PATCH;
        else if (mlen == 5 && ngx_strncasecmp(start, (u_char *)"TRACE", 5) == 0)
            m |= NGX_HTTP_TRACE;
        else if (mlen == 8 && ngx_strncasecmp(start, (u_char *)"PROPFIND", 8) == 0)
            m |= NGX_HTTP_PROPFIND;
        else if (mlen == 9 && ngx_strncasecmp(start, (u_char *)"PROPPATCH", 9) == 0)
            m |= NGX_HTTP_PROPPATCH;
        else if (mlen == 4 && ngx_strncasecmp(start, (u_char *)"COPY", 4) == 0)
            m |= NGX_HTTP_COPY;
        else if (mlen == 4 && ngx_strncasecmp(start, (u_char *)"MOVE", 4) == 0)
            m |= NGX_HTTP_MOVE;
        else if (mlen == 5 && ngx_strncasecmp(start, (u_char *)"MKCOL", 5) == 0)
            m |= NGX_HTTP_MKCOL;
        else if (mlen == 4 && ngx_strncasecmp(start, (u_char *)"LOCK", 4) == 0)
            m |= NGX_HTTP_LOCK;
        else if (mlen == 6 && ngx_strncasecmp(start, (u_char *)"UNLOCK", 6) == 0)
            m |= NGX_HTTP_UNLOCK;
        /* unknown method names are ignored */
    }
    return m;
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

    /* ---- Require ----
     *
     * Inside a <RequireNone> block the sense is inverted: access is DENIED to
     * anything the inner Require matches. We map "Require ip/host/env" to a
     * Deny ACL entry (and "Require all granted" to Deny-all) so a ban list
     * like "<RequireNone> Require ip 1.2.3.4 </RequireNone>" actually blocks
     * that client instead of flattening into an allow (which was fail-open).
     */
    if (ngx_strcasecmp(args[0], (u_char *)"Require") == 0 && n >= 2) {
        unsigned none = h->in_require_none;
        if (ngx_strcasecmp(args[1], (u_char *)"all") == 0 && n >= 3) {
            if (ngx_strcasecmp(args[2], (u_char *)"granted") == 0)
                { if (none) h->require_denied = 1; else h->require_granted = 1; }
            else if (ngx_strcasecmp(args[2], (u_char *)"denied") == 0)
                { if (!none) h->require_denied = 1; }
        } else if (ngx_strcasecmp(args[1], (u_char *)"valid-user") == 0) {
            h->auth_valid_user = 1;
        } else if (ngx_strcasecmp(args[1], (u_char *)"user") == 0) {
            ngx_uint_t i;
            for (i = 2; i < n && h->nauth_users < HTA_MAX_USERS; i++) {
                h->auth_users[h->nauth_users].data = args[i];
                h->auth_users[h->nauth_users].len = ngx_strlen(args[i]);
                h->nauth_users++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"group") == 0) {
            ngx_uint_t i;
            for (i = 2; i < n && h->nrequire_groups < HTA_MAX_GROUPS; i++) {
                h->require_groups[h->nrequire_groups].data = args[i];
                h->require_groups[h->nrequire_groups].len = ngx_strlen(args[i]);
                h->nrequire_groups++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"ip") == 0 ||
                   ngx_strcasecmp(args[1], (u_char *)"host") == 0) {
            ngx_uint_t i;
            if (none) h->has_acl = 1; else h->has_require_host = 1;
            for (i = 2; i < n && h->nacl < HTA_MAX_USERS; i++) {
                h->acl[h->nacl].value.data = args[i];
                h->acl[h->nacl].value.len = ngx_strlen(args[i]);
                h->acl[h->nacl].is_allow = none ? 0 : 1;
                h->acl[h->nacl].is_require = none ? 0 : 1;
                h->nacl++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"env") == 0) {
            ngx_uint_t i;
            if (none) h->has_acl = 1; else h->has_require_host = 1;
            for (i = 2; i < n && h->nacl < HTA_MAX_USERS; i++) {
                size_t  al = ngx_strlen(args[i]);
                u_char *v  = ngx_pnalloc(h->pool, 4 + al);
                if (v == NULL) continue;
                ngx_memcpy(v, "env=", 4);
                ngx_memcpy(v + 4, args[i], al);
                h->acl[h->nacl].value.data = v;
                h->acl[h->nacl].value.len  = 4 + al;
                h->acl[h->nacl].is_allow   = none ? 0 : 1;
                h->acl[h->nacl].is_require = none ? 0 : 1;
                h->nacl++;
            }
        } else if (ngx_strcasecmp(args[1], (u_char *)"local") == 0) {
            h->require_local = 1;
        } else {
            /* Unsupported Require provider (expr, method, not, forward-dns,
             * ...). Fail closed rather than silently granting access. */
            h->require_failed = 1;
            ngx_log_error(NGX_LOG_WARN, log, 0,
                "htaccess: unsupported \"Require %s\", denying scope",
                args[1]);
        }
        return;
    }

    /* ---- Satisfy Any/All ----
     *
     * Default is All: when BOTH access control (Allow/Deny/Require ip) AND
     * auth (Require valid-user/user/group) are configured, both must pass.
     * Satisfy Any: either one is sufficient.
     */
    if (ngx_strcasecmp(args[0], (u_char *)"Satisfy") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"any") == 0)
            h->satisfy = HTA_SATISFY_ANY;
        else
            h->satisfy = HTA_SATISFY_ALL;
        return;
    }

    /* ---- AuthGroupFile ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthGroupFile") == 0 && n >= 2) {
        h->auth_group_file.data = args[1];
        h->auth_group_file.len = ngx_strlen(args[1]);
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

            /* optional trailing "env=[!]VAR" condition (e.g. conditional CORS
             * "Header set Access-Control-Allow-Origin * env=CORS_OK") */
            if (n > off + 1
                && ngx_strncmp(args[n-1], (u_char *)"env=", 4) == 0)
            {
                u_char *e = args[n-1] + 4;
                if (*e == '!') { hd->cond_negate = 1; e++; }
                hd->cond_env.data = e;
                hd->cond_env.len  = ngx_strlen(e);
                /* env= was misread as the value (set with no real value) */
                if (hd->value.data == args[n-1]) {
                    hd->value.data = NULL; hd->value.len = 0;
                }
            }
            h->nheaders++;
        }
        return;
    }

    /* ---- RequestHeader ----
     *
     * Modifies r->headers_in (the incoming request) before it is handed to
     * upstreams (fastcgi/proxy). Supports set/add/append/unset; the rarely
     * used `edit`/`edit*` regex-replace forms are accepted as no-ops.
     */
    if (ngx_strcasecmp(args[0], (u_char *)"RequestHeader") == 0 && n >= 2) {
        if (h->nreq_headers < HTA_MAX_REQ_HEADERS) {
            hta_header_t *hd = &h->req_headers[h->nreq_headers];
            ngx_uint_t    off = 1;
            u_char       *act = args[1];

            if      (ngx_strcasecmp(act, (u_char *)"set") == 0)    hd->action = HTA_HDR_SET;
            else if (ngx_strcasecmp(act, (u_char *)"unset") == 0)  hd->action = HTA_HDR_UNSET;
            else if (ngx_strcasecmp(act, (u_char *)"append") == 0) hd->action = HTA_HDR_APPEND;
            else if (ngx_strcasecmp(act, (u_char *)"add") == 0)    hd->action = HTA_HDR_ADD;
            else if (ngx_strcasecmp(act, (u_char *)"merge") == 0)  hd->action = HTA_HDR_MERGE;
            else if (ngx_strcasecmp(act, (u_char *)"edit") == 0
                     || ngx_strcasecmp(act, (u_char *)"edit*") == 0) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "htaccess: RequestHeader edit/edit* not supported, "
                    "directive ignored");
                return;
            } else return;

            off++;
            if (n <= off) return;

            hd->name.data = args[off];
            hd->name.len = ngx_strlen(args[off]);
            hta_strip_crlf(hd->name.data, &hd->name.len);

            if (hd->action != HTA_HDR_UNSET && n > off + 1) {
                hd->value.data = args[off + 1];
                hd->value.len = ngx_strlen(args[off + 1]);
                hta_strip_crlf(hd->value.data, &hd->value.len);
            }
            h->nreq_headers++;
        }
        return;
    }

    /* ---- AuthType ---- */
    if (ngx_strcasecmp(args[0], (u_char *)"AuthType") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"Basic") == 0) {
            h->auth_basic = 1;
            h->auth_type_unsupported = 0;
        } else {
            /* Digest or any other scheme is not implemented; mark it so the
             * auth check fails closed instead of silently disabling auth. */
            h->auth_basic = 0;
            h->auth_type_unsupported = 1;
        }
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

    /* ---- FallbackResource ----
     * Front-controller fallback: when the request maps to no existing file,
     * serve this resource instead (mod_dir). "disabled" clears an inherited
     * setting. */
    if (ngx_strcasecmp(args[0], (u_char *)"FallbackResource") == 0 && n >= 2) {
        if (ngx_strcasecmp(args[1], (u_char *)"disabled") == 0) {
            h->fallback_resource.data = NULL;
            h->fallback_resource.len  = 0;
        } else {
            h->fallback_resource.data = args[1];
            h->fallback_resource.len  = ngx_strlen(args[1]);
        }
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

    /* ---- SetEnvIf / SetEnvIfNoCase / BrowserMatch / BrowserMatchNoCase ----
     *
     * SetEnvIf          attribute regex env[=val]...
     * SetEnvIfNoCase    attribute regex env[=val]...    (case-insensitive regex)
     * BrowserMatch      regex      env[=val]...         (User-Agent shorthand)
     * BrowserMatchNoCase regex     env[=val]...
     *
     * Multiple env=val tokens are supported (one struct per token), matching
     * Apache semantics. `!env` removes the variable instead of setting it.
     */
    {
        unsigned   is_nocase = 0;
        unsigned   is_browser = 0;
        unsigned   handled = 0;

        if (ngx_strcasecmp(args[0], (u_char *)"SetEnvIf") == 0) handled = 1;
        else if (ngx_strcasecmp(args[0], (u_char *)"SetEnvIfNoCase") == 0) {
            handled = 1; is_nocase = 1;
        } else if (ngx_strcasecmp(args[0], (u_char *)"BrowserMatch") == 0) {
            handled = 1; is_browser = 1;
        } else if (ngx_strcasecmp(args[0], (u_char *)"BrowserMatchNoCase") == 0) {
            handled = 1; is_browser = 1; is_nocase = 1;
        }

        if (handled) {
            ngx_uint_t          first_env;
            ngx_uint_t          ei;
            ngx_regex_t        *regex = NULL;
            ngx_str_t           attr, patt;
            ngx_regex_compile_t rc;
            u_char              errbuf[256];

            if (is_browser) {
                if (n < 3) return;
                ngx_str_set(&attr, "User-Agent");
                patt.data = args[1]; patt.len = ngx_strlen(args[1]);
                first_env = 2;
            } else {
                if (n < 4) return;
                attr.data = args[1]; attr.len = ngx_strlen(args[1]);
                patt.data = args[2]; patt.len = ngx_strlen(args[2]);
                first_env = 3;
            }

            ngx_memzero(&rc, sizeof(rc));
            rc.pattern = patt;
            rc.pool = h->pool;
            rc.err.data = errbuf;
            rc.err.len = sizeof(errbuf);
            if (is_nocase) rc.options = NGX_REGEX_CASELESS;
            if (ngx_regex_compile(&rc) == NGX_OK) regex = rc.regex;

            for (ei = first_env; ei < n && h->nsetenvifs < HTA_MAX_SETENVIF;
                 ei++)
            {
                hta_setenvif_t *se = &h->setenvifs[h->nsetenvifs];
                u_char         *tok = args[ei];
                u_char         *eq;

                ngx_memzero(se, sizeof(hta_setenvif_t));
                se->attribute = attr;
                se->pattern   = patt;
                se->regex     = regex;

                /* leading '!' = unset the variable on match */
                if (tok[0] == '!') {
                    se->unset = 1;
                    tok++;
                }
                eq = (u_char *)ngx_strchr(tok, '=');
                if (eq) {
                    se->env_name.data = tok;
                    se->env_name.len  = eq - tok;
                    se->env_value.data = eq + 1;
                    se->env_value.len  = ngx_strlen(eq + 1);
                } else {
                    se->env_name.data = tok;
                    se->env_name.len  = ngx_strlen(tok);
                    ngx_str_set(&se->env_value, "1");
                }

                if (se->env_name.len == 0) continue;
                h->nsetenvifs++;
            }
            return;
        }
    }

    /* ---- SetEnv (unconditional) ----
     *
     *   SetEnv name [value]
     *   UnsetEnv name
     */
    if ((ngx_strcasecmp(args[0], (u_char *)"SetEnv") == 0
         || ngx_strcasecmp(args[0], (u_char *)"UnsetEnv") == 0)
        && n >= 2)
    {
        unsigned is_unset = (ngx_strcasecmp(args[0], (u_char *)"UnsetEnv") == 0);

        if (h->nsetenvifs < HTA_MAX_SETENVIF) {
            hta_setenvif_t *se = &h->setenvifs[h->nsetenvifs];
            ngx_memzero(se, sizeof(hta_setenvif_t));
            se->unconditional = 1;
            se->unset         = is_unset;
            se->env_name.data = args[1];
            se->env_name.len  = ngx_strlen(args[1]);
            if (!is_unset && n >= 3) {
                se->env_value.data = args[2];
                se->env_value.len  = ngx_strlen(args[2]);
            } else {
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

    /* ---- php_value / php_admin_value / php_flag / php_admin_flag ----
     *
     * Translated to fastcgi PHP_VALUE / PHP_ADMIN_VALUE entries that the
     * user injects via the $htaccess_php_value / $htaccess_php_admin_value
     * variables, e.g.:
     *   location ~ \.php$ {
     *       fastcgi_param PHP_VALUE       $htaccess_php_value;
     *       fastcgi_param PHP_ADMIN_VALUE $htaccess_php_admin_value;
     *   }
     */
    if (ngx_strncasecmp(args[0], (u_char *)"php_", 4) == 0 && n >= 3) {
        u_char    *d = args[0] + 4;
        unsigned   is_admin = 0;
        unsigned   is_known = 0;

        if (ngx_strncasecmp(d, (u_char *)"admin_", 6) == 0) {
            is_admin = 1;
            d += 6;
        }
        if (ngx_strcasecmp(d, (u_char *)"value") == 0
            || ngx_strcasecmp(d, (u_char *)"flag") == 0)
        {
            is_known = 1;
        }

        /* "php_flag engine off" (or php_admin_flag/php_value) is the classic
         * upload-dir kill-switch. FPM has no "engine" ini so exposing it via
         * PHP_VALUE is a no-op; enforce it directly by blocking execution. */
        if (is_known && ngx_strcasecmp(args[1], (u_char *)"engine") == 0
            && (ngx_strcasecmp(args[2], (u_char *)"off") == 0
                || ngx_strcasecmp(args[2], (u_char *)"0") == 0
                || ngx_strcasecmp(args[2], (u_char *)"false") == 0))
        {
            h->exec_disabled = 1;
        }

        if (is_known && h->nphp_values < HTA_MAX_PHP_VALUES) {
            hta_php_value_t *pv = &h->php_values[h->nphp_values];
            pv->name.data  = args[1];
            pv->name.len   = ngx_strlen(args[1]);
            pv->value.data = args[2];
            pv->value.len  = ngx_strlen(args[2]);
            pv->is_admin   = is_admin;

            /* defang the value: '\n' or '"' would corrupt PHP_VALUE syntax */
            {
                u_char    *vp = pv->value.data;
                ngx_uint_t k;
                for (k = 0; k < pv->value.len; k++) {
                    if (vp[k] == '\n' || vp[k] == '\r'
                        || vp[k] == '"'  || vp[k] == '\0')
                        vp[k] = ' ';
                }
            }
            h->nphp_values++;
        } else if (!is_known) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                "htaccess: ignoring unknown PHP directive \"%s\"", args[0]);
        }
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

    /* Satisfy is handled above (see "Satisfy Any/All") */

    /* ---- SetHandler ----
     * "SetHandler none" / "default-handler" is the upload-dir kill-switch that
     * turns off script execution; honor it by blocking execution of scripts in
     * this scope (see hta_check_exec). Any other value is ignored. */
    if (ngx_strcasecmp(args[0], (u_char *)"SetHandler") == 0) {
        if (n >= 2
            && (ngx_strcasecmp(args[1], (u_char *)"none") == 0
                || ngx_strcasecmp(args[1], (u_char *)"default-handler") == 0))
        {
            h->exec_disabled = 1;
        }
        return;
    }

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
    /* RemoveHandler .php (upload-dir hardening) - block script execution */
    if (ngx_strcasecmp(args[0], (u_char *)"RemoveHandler") == 0) {
        ngx_uint_t i;
        for (i = 1; i < n; i++)
            if (hta_token_has_php(args[i])) { h->exec_disabled = 1; break; }
        return;
    }
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
    /* BrowserMatch / BrowserMatchNoCase handled above with SetEnvIf family */
    if (ngx_strcasecmp(args[0], (u_char *)"SSLOptions") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SSLRequireSSL") == 0) {
        h->ssl_required = 1;
        return;
    }
    /* SSLRequire takes an Apache expression; we treat any form as "require HTTPS" */
    if (ngx_strcasecmp(args[0], (u_char *)"SSLRequire") == 0) {
        h->ssl_required = 1;
        return;
    }
    if (ngx_strcasecmp(args[0], (u_char *)"Action") == 0) return;
    /* SetEnvIfNoCase, UnsetEnv handled above with SetEnvIf family */
    /* RequestHeader handled above with response Header */
    if (ngx_strcasecmp(args[0], (u_char *)"PassEnv") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecFilterEngine") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecFilterScanPOST") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecRule") == 0) return;
    if (ngx_strcasecmp(args[0], (u_char *)"SecAction") == 0) return;

    /* Unrecognized directive. Record it and warn so it is not silently lost;
     * with `htaccess_strict on;` the access handler turns this into a 500
     * (fail closed, matching Apache) instead of ignoring a possibly
     * security-relevant directive. */
    h->has_unknown = 1;
    ngx_log_error(NGX_LOG_WARN, log, 0,
        "htaccess: unknown directive \"%s\" ignored", args[0]);
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

    /* <Limit ...>, <LimitExcept ...> - handled separately by file parser */
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
    hta_limit_block_t *cur_lb;
    ngx_int_t          limit_depth;
    ngx_int_t          require_none_depth;

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
    cur_lb = NULL;     /* non-NULL = inside <Limit>/<LimitExcept> block */
    limit_depth = 0;
    require_none_depth = 0;  /* >0 = inside <RequireNone> (invert to Deny) */

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
                            } else if (cur_lb) {
                                if (limit_depth > 0) {
                                    limit_depth--;
                                } else {
                                    cur_lb = NULL;
                                }
                            } else if (require_none_depth > 0) {
                                require_none_depth--;
                                if (require_none_depth == 0)
                                    h->in_require_none = 0;
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
                            } else if (cur_lb) {
                                /* nested inside <Limit> - skip (not supported) */
                                skip_depth = 1;
                            } else if (ngx_strncasecmp(trimmed + 1,
                                           (u_char *)"LimitExcept", 11) == 0
                                       || ngx_strncasecmp(trimmed + 1,
                                           (u_char *)"Limit ", 6) == 0
                                       || ngx_strncasecmp(trimmed + 1,
                                           (u_char *)"Limit>", 6) == 0)
                            {
                                /* <Limit ...> / <LimitExcept ...>: always
                                 * consume the inner block so directives
                                 * don't leak into the global scope, even if
                                 * the per-file cap is reached. */
                                if (h->nlimit_blocks
                                        < HTA_MAX_LIMIT_BLOCKS)
                                {
                                    hta_limit_block_t *lb =
                                        &h->limit_blocks[h->nlimit_blocks];
                                    u_char *ps, *pe;

                                    ngx_memzero(lb, sizeof(hta_limit_block_t));

                                    lb->is_except = (ngx_strncasecmp(trimmed + 1,
                                        (u_char *)"LimitExcept", 11) == 0);

                                    ps = trimmed + (lb->is_except ? 12 : 6);
                                    pe = trimmed + tlen - 1;
                                    lb->methods = hta_parse_methods(ps, pe);

                                    if (lb->methods == 0) {
                                        ngx_log_error(NGX_LOG_WARN, log, 0,
                                            "htaccess: <Limit> with no "
                                            "recognized methods, block "
                                            "will be inert");
                                    }

                                    cur_lb = lb;
                                    h->nlimit_blocks++;
                                } else {
                                    ngx_log_error(NGX_LOG_WARN, log, 0,
                                        "htaccess: too many <Limit> blocks, "
                                        "skipping");
                                    skip_depth = 1;
                                }
                            } else if (ngx_strncasecmp(trimmed + 1,
                                           (u_char *)"Files", 5) == 0)
                            {
                                /* entering <Files>/<FilesMatch>. If the per-file
                                 * cap is reached, fail closed (skip the block)
                                 * so its access/auth directives cannot leak into
                                 * the global scope. */
                                if (h->nfiles_blocks >= HTA_MAX_FILES_BLOCKS) {
                                    ngx_log_error(NGX_LOG_WARN, log, 0,
                                        "htaccess: too many <Files> blocks, "
                                        "skipping");
                                    skip_depth = 1;
                                } else {
                                hta_files_block_t *fb =
                                    &h->files_blocks[h->nfiles_blocks];
                                u_char *ps;
                                u_char *pe;

                                ngx_memzero(fb, sizeof(hta_files_block_t));

                                fb->is_regex = (ngx_strncasecmp(trimmed + 1,
                                    (u_char *)"FilesMatch", 10) == 0);

                                /* extract pattern from tag:
                                 * <Files "pattern">, <FilesMatch "regex"> or
                                 * the tilde regex form <Files ~ "regex">
                                 */
                                ps = trimmed + (fb->is_regex ? 12 : 7);
                                while (*ps == ' ' || *ps == '\t') ps++;
                                if (*ps == '~') {
                                    /* <Files ~ "re"> is a regex match, like
                                     * <FilesMatch>. Without this the "~ ..."
                                     * was stored as a literal filename that
                                     * never matched (Deny rules failed open). */
                                    fb->is_regex = 1;
                                    ps++;
                                    while (*ps == ' ' || *ps == '\t') ps++;
                                }
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
                                }
                            } else if (ngx_strncasecmp(trimmed + 1,
                                           (u_char *)"RequireNone", 11) == 0) {
                                /* enter <RequireNone>: inner Require ip/host/env
                                 * are parsed inline but inverted to Deny */
                                require_none_depth++;
                                h->in_require_none = 1;
                            } else if (!hta_should_enter_block(
                                           trimmed, tlen)) {
                                skip_depth = 1;
                            }
                            /* if entering a non-Files block, skip tag line */
                        } else if (skip_depth == 0) {
                            if (cur_fb) {
                                hta_parse_line_fb(cur_fb, wl, parse_len,
                                                  pool, log);
                            } else if (cur_lb) {
                                hta_parse_line_lb(cur_lb, wl, parse_len,
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
