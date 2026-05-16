/*
 * ngx_http_htaccess_module.c - Native .htaccess support for nginx
 *
 * Core module: definition, configuration, phase handler entry points,
 * directory traversal for .htaccess file collection.
 *
 * Supported directives:
 *   RewriteEngine, RewriteBase, RewriteRule, RewriteCond
 *   DirectoryIndex, ErrorDocument
 *   Options (±Indexes, ±FollowSymLinks, ±MultiViews)
 *   Order, Allow, Deny (access control)
 *   Require (all granted/denied, ip, host, valid-user, user)
 *   Header set/unset/append/add/merge
 *   AuthType Basic, AuthName, AuthUserFile
 *   ForceType, DefaultType, AddType
 *   ExpiresActive, ExpiresDefault, ExpiresByType
 *   SetEnvIf
 *   SSLRequireSSL, SSLRequire (require HTTPS)
 *   php_value, php_admin_value, php_flag, php_admin_flag
 *     (exposed via $htaccess_php_value / $htaccess_php_admin_value)
 *   <IfModule>, <Files>, <FilesMatch>, <Limit>, <LimitExcept>
 *
 * Features:
 *   - Nested .htaccess traversal (root → deepest directory)
 *   - Parsed result caching with inotify invalidation
 *   - Dynamic module (.so) support
 *   - Per-location enable/disable
 *   - Line continuation (backslash)
 *   - Quoted arguments
 *
 * License: BSD-2-Clause
 */

#include "ngx_http_htaccess_module.h"
#include <sys/inotify.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t hta_preconfigure(ngx_conf_t *cf);
static ngx_int_t hta_postconfigure(ngx_conf_t *cf);
static ngx_int_t hta_init_process(ngx_cycle_t *cycle);
static void      hta_exit_process(ngx_cycle_t *cycle);
static void     *hta_create_main(ngx_conf_t *cf);
static void     *hta_create_loc(ngx_conf_t *cf);
static char     *hta_merge_loc(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t hta_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t hta_preaccess_handler(ngx_http_request_t *r);
static ngx_int_t hta_access_handler(ngx_http_request_t *r);

static ngx_int_t hta_var_php_value(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t is_admin);


/* ═══════════════════════════════════════════════════════════════════════════
 * Module definition
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_command_t hta_commands[] = {
    { ngx_string("htaccess"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, enable),
      NULL },

    { ngx_string("htaccess_filename"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, filename),
      NULL },

    ngx_null_command
};

static ngx_http_module_t hta_module_ctx = {
    hta_preconfigure,        /* preconfiguration */
    hta_postconfigure,       /* postconfiguration */
    hta_create_main,         /* create main conf */
    NULL,                    /* init main conf */
    NULL,                    /* create server conf */
    NULL,                    /* merge server conf */
    hta_create_loc,          /* create location conf */
    hta_merge_loc            /* merge location conf */
};

ngx_module_t ngx_http_htaccess_module = {
    NGX_MODULE_V1,
    &hta_module_ctx,
    hta_commands,
    NGX_HTTP_MODULE,
    NULL, NULL,
    hta_init_process,
    NULL, NULL,
    hta_exit_process,
    NULL,
    NGX_MODULE_V1_PADDING
};


/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════ */

static void *
hta_create_main(ngx_conf_t *cf)
{
    ngx_http_hta_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hta_main_conf_t));
    if (conf == NULL) return NULL;
    conf->inotify_fd = -1;
    return conf;
}

static void *
hta_create_loc(ngx_conf_t *cf)
{
    ngx_http_hta_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hta_loc_conf_t));
    if (conf == NULL) return NULL;
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *
hta_merge_loc(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hta_loc_conf_t *prev = parent;
    ngx_http_hta_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->filename, prev->filename, ".htaccess");
    return NGX_CONF_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Preconfiguration - register nginx variables
 *
 * $htaccess_php_value, $htaccess_php_admin_value: newline-separated
 * "name=value" pairs collected from php_value / php_admin_value / php_flag /
 * php_admin_flag directives. Wire them into fastcgi via:
 *   fastcgi_param PHP_VALUE       $htaccess_php_value;
 *   fastcgi_param PHP_ADMIN_VALUE $htaccess_php_admin_value;
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_http_variable_t hta_vars[] = {
    { ngx_string("htaccess_php_value"), NULL,
      hta_var_php_value, 0, 0, 0 },
    { ngx_string("htaccess_php_admin_value"), NULL,
      hta_var_php_value, 1, 0, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t
hta_preconfigure(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *vp;

    for (vp = hta_vars; vp->name.len; vp++) {
        v = ngx_http_add_variable(cf, &vp->name, vp->flags);
        if (v == NULL) return NGX_ERROR;
        v->get_handler = vp->get_handler;
        v->data = vp->data;
    }
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Postconfiguration - register phase handlers and header filter
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_postconfigure(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* rewrite phase - URL rewriting & directory index */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = hta_rewrite_handler;

    /* preaccess phase - re-apply SetEnvIf/SetEnv so its values stick AFTER
     * any `set $foo "";` in the location's rewrite script (nginx reverses
     * REWRITE_PHASE handler order, so our handler there runs BEFORE `set`). */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = hta_preaccess_handler;

    /* access phase - access control & auth */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = hta_access_handler;

    /* header filter - response headers, expires, content-type */
    hta_header_filter_init(ngx_http_top_header_filter);
    ngx_http_top_header_filter = hta_header_filter;

    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Process init/exit - inotify setup and cleanup
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_init_process(ngx_cycle_t *cycle)
{
    ngx_http_hta_main_conf_t *conf;
    conf = ngx_http_cycle_get_module_main_conf(cycle,
                                                ngx_http_htaccess_module);
    if (conf == NULL) return NGX_OK;

    conf->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (conf->inotify_fd == -1) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
            "htaccess: inotify_init1() failed, using stat() fallback");
    }

    conf->path_pool = ngx_create_pool(4096, cycle->log);
    if (conf->path_pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
            "htaccess: failed to create path pool");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
hta_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_hta_main_conf_t *conf;
    ngx_uint_t i;

    conf = ngx_http_cycle_get_module_main_conf(cycle,
                                                ngx_http_htaccess_module);
    if (conf == NULL) return;

    /* cleanup cache pools */
    for (i = 0; i < conf->ncache; i++) {
        if (conf->cache[i].parsed && conf->cache[i].parsed->pool) {
            ngx_destroy_pool(conf->cache[i].parsed->pool);
            conf->cache[i].parsed = NULL;
        }
        if (conf->inotify_fd != -1 && conf->cache[i].wd != -1) {
            inotify_rm_watch(conf->inotify_fd, conf->cache[i].wd);
        }
    }

    if (conf->inotify_fd != -1) {
        close(conf->inotify_fd);
        conf->inotify_fd = -1;
    }

    if (conf->path_pool) {
        ngx_destroy_pool(conf->path_pool);
        conf->path_pool = NULL;
    }

    /* cleanup passwd cache pools */
    for (i = 0; i < conf->npasswd; i++) {
        if (conf->passwd[i].pool) {
            ngx_destroy_pool(conf->passwd[i].pool);
            conf->passwd[i].pool = NULL;
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Directory traversal - find all .htaccess files from root to deepest dir
 * ═══════════════════════════════════════════════════════════════════════ */

void
hta_collect_files(ngx_http_request_t *r, ngx_str_t *root, ngx_str_t *filename,
    hta_file_list_t *list)
{
    u_char          path[HTA_MAX_PATH];
    ngx_int_t       plen;
    ngx_file_info_t fi;
    u_char         *uri_p, *uri_end;
    u_char          dir[HTA_MAX_PATH];
    ngx_int_t       dlen;

    list->count = 0;

    /* document root */
    plen = ngx_snprintf(path, sizeof(path) - 1,
                        "%V/%V", root, filename) - path;
    path[plen] = '\0';
    if (ngx_file_info(path, &fi) == 0 && ngx_is_file(&fi)) {
        list->files[list->count].data = ngx_pnalloc(r->pool, plen + 1);
        if (list->files[list->count].data) {
            ngx_memcpy(list->files[list->count].data, path, plen + 1);
            list->files[list->count].len = plen;
            list->count++;
        }
    }

    /* walk URI segments */
    dlen = root->len;
    ngx_memcpy(dir, root->data, dlen);

    uri_p = r->uri.data;
    uri_end = r->uri.data + r->uri.len;
    if (uri_p < uri_end && *uri_p == '/') uri_p++;

    while (uri_p < uri_end && list->count < HTA_MAX_DEPTH) {
        u_char     *seg;
        ngx_uint_t  slen;

        seg = uri_p;
        while (uri_p < uri_end && *uri_p != '/') uri_p++;
        if (uri_p >= uri_end) break;  /* last segment is file, not dir */

        slen = uri_p - seg;

        /* Security: skip ".." segments to prevent path traversal */
        if (slen == 2 && seg[0] == '.' && seg[1] == '.') {
            uri_p++;
            continue;
        }
        /* skip empty segments ("//") and current dir (".") */
        if (slen == 0 || (slen == 1 && seg[0] == '.')) {
            uri_p++;
            continue;
        }

        if (dlen + 1 + (ngx_int_t)slen >= HTA_MAX_PATH - 1) break;

        dir[dlen] = '/';
        ngx_memcpy(dir + dlen + 1, seg, slen);
        dlen += 1 + slen;
        dir[dlen] = '\0';

        plen = ngx_snprintf(path, sizeof(path) - 1,
                            "%s/%V", dir, filename) - path;
        path[plen] = '\0';

        if (ngx_file_info(path, &fi) == 0 && ngx_is_file(&fi)) {
            list->files[list->count].data = ngx_pnalloc(r->pool, plen + 1);
            if (list->files[list->count].data) {
                ngx_memcpy(list->files[list->count].data, path, plen + 1);
                list->files[list->count].len = plen;
                list->count++;
            }
        }

        uri_p++;  /* skip '/' */
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Request-context file list cache - eliminates duplicate stat() calls
 * across rewrite, access, and header-filter phases for the same URI
 * ═══════════════════════════════════════════════════════════════════════ */

hta_file_list_t *
hta_get_files(ngx_http_request_t *r, ngx_str_t *root, ngx_str_t *filename)
{
    hta_req_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_htaccess_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(hta_req_ctx_t));
        if (ctx == NULL) return NULL;
        ngx_http_set_ctx(r, ctx, ngx_http_htaccess_module);
    }

    /* reuse if URI hasn't changed since last collection */
    if (ctx->collected
        && ctx->uri.len == r->uri.len
        && ngx_memcmp(ctx->uri.data, r->uri.data, r->uri.len) == 0)
    {
        return &ctx->files;
    }

    hta_collect_files(r, root, filename, &ctx->files);
    ctx->uri = r->uri;
    ctx->collected = 1;

    return &ctx->files;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Variable handler: $htaccess_php_value / $htaccess_php_admin_value
 *
 * Walks the .htaccess chain for the request and concatenates collected
 * php_value/php_flag entries matching the admin/non-admin flag, formatted
 * as "name=value\nname=value\n..." for fastcgi PHP_VALUE consumption.
 *
 * Empty string when nothing collected — the fastcgi module treats an empty
 * PHP_VALUE param as a no-op, matching the "no .htaccess" case.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_var_php_value(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t is_admin)
{
    ngx_http_hta_loc_conf_t   *lcf;
    ngx_http_hta_main_conf_t  *mc;
    ngx_http_core_loc_conf_t  *clcf;
    hta_file_list_t           *files;
    hta_parsed_t              *parsed_list[HTA_MAX_DEPTH];
    ngx_uint_t                 nparsed = 0;
    ngx_uint_t                 i, j;
    size_t                     total = 0;
    u_char                    *buf, *p;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = 0;
    v->data = (u_char *) "";

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (lcf == NULL || !lcf->enable) return NGX_OK;

    mc = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (mc == NULL || clcf == NULL || clcf->root.len == 0) return NGX_OK;

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL || files->count == 0) return NGX_OK;

    /* first pass: collect parsed files and total output size */
    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL) continue;
        if (nparsed >= HTA_MAX_DEPTH) break;
        parsed_list[nparsed++] = h;

        for (j = 0; j < h->nphp_values; j++) {
            hta_php_value_t *pv = &h->php_values[j];
            if ((pv->is_admin ? 1u : 0u) != (ngx_uint_t) is_admin) continue;
            total += pv->name.len + 1 + pv->value.len + 1; /* name=value\n */
        }
    }
    if (total == 0) return NGX_OK;

    buf = ngx_pnalloc(r->pool, total);
    if (buf == NULL) return NGX_ERROR;
    p = buf;

    for (i = 0; i < nparsed; i++) {
        hta_parsed_t *h = parsed_list[i];
        for (j = 0; j < h->nphp_values; j++) {
            hta_php_value_t *pv = &h->php_values[j];
            if ((pv->is_admin ? 1u : 0u) != (ngx_uint_t) is_admin) continue;
            p = ngx_cpymem(p, pv->name.data, pv->name.len);
            *p++ = '=';
            p = ngx_cpymem(p, pv->value.data, pv->value.len);
            *p++ = '\n';
        }
    }

    /* trim trailing newline */
    if (p > buf && p[-1] == '\n') p--;

    v->data = buf;
    v->len  = p - buf;
    return NGX_OK;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Rewrite phase handler - entry point
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_hta_loc_conf_t   *lcf;
    ngx_http_hta_main_conf_t  *mc;
    ngx_http_core_loc_conf_t  *clcf;
    hta_file_list_t           *files;
    ngx_uint_t                 i;
    ngx_int_t                  rc;

    if (r != r->main) return NGX_DECLINED;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return NGX_DECLINED;

    mc  = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->root.len == 0) return NGX_DECLINED;

    /* inotify: poll every 64 requests (amortize read() syscall);
     * stat-fallback: poll every request (no fd, just state check) */
    if (mc->inotify_fd == -1 || (++mc->poll_counter & 63) == 0)
        hta_inotify_poll(mc, r->connection->log);

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL) return NGX_DECLINED;

    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h;

        h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL) continue;

        /* apply SetEnvIf early (before rewrite rules) */
        hta_apply_setenvif(r, h);

        /* mutate request headers before upstream phases see them */
        hta_apply_request_headers(r, h);

        rc = hta_apply_dirindex(r, h);
        if (rc != NGX_DECLINED) return rc;

        rc = hta_apply_redirects(r, h);
        if (rc != NGX_DECLINED) return rc;

        rc = hta_apply_rules(r, h);
        if (rc != NGX_DECLINED) return rc;
    }

    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Preaccess phase handler - re-apply SetEnvIf/SetEnv
 *
 * The rewrite phase reverses handler order, so our REWRITE_PHASE handler
 * runs BEFORE nginx's rewrite-module script. If the user's nginx.conf has
 * `set $foo "";` to declare a variable, that `set` overwrites the value we
 * computed from SetEnv/SetEnvIf. Re-apply here, after the rewrite script
 * has fully run, so the final variable value reflects .htaccess intent.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_preaccess_handler(ngx_http_request_t *r)
{
    ngx_http_hta_loc_conf_t   *lcf;
    ngx_http_hta_main_conf_t  *mc;
    ngx_http_core_loc_conf_t  *clcf;
    hta_file_list_t           *files;
    ngx_uint_t                 i;

    if (r != r->main) return NGX_DECLINED;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return NGX_DECLINED;

    mc   = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->root.len == 0) return NGX_DECLINED;

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL) return NGX_DECLINED;

    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL) continue;
        hta_apply_setenvif(r, h);
    }

    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Access phase handler - entry point
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_access_handler(ngx_http_request_t *r)
{
    ngx_http_hta_loc_conf_t   *lcf;
    ngx_http_hta_main_conf_t  *mc;
    ngx_http_core_loc_conf_t  *clcf;
    hta_file_list_t           *files;
    ngx_uint_t                 i;
    ngx_int_t                  rc;
    hta_parsed_t              *parsed_list[HTA_MAX_DEPTH];
    ngx_uint_t                 nparsed = 0;

    if (r != r->main) return NGX_DECLINED;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return NGX_DECLINED;

    /* Security: block direct access to .htaccess, .htpasswd and similar.
     * Fast path: last URI component must start with ".ht" to need full check. */
    {
        u_char *last = r->uri.data + r->uri.len;
        u_char *p    = last;
        while (p > r->uri.data && p[-1] != '/') p--;
        /* p now points to the start of the basename */
        if ((last - p) >= 3
            && p[0] == '.'
            && (p[1] == 'h' || p[1] == 'H')
            && (p[2] == 't' || p[2] == 'T'))
        {
            ngx_uint_t blen = last - p;
            if ((blen == 9
                 && ngx_strncasecmp(p, (u_char *)".htaccess", 9) == 0)
                || (blen == 9
                    && ngx_strncasecmp(p, (u_char *)".htpasswd", 9) == 0)
                || (blen == 8
                    && ngx_strncasecmp(p, (u_char *)".htgroup", 8) == 0)
                || (blen == 9
                    && ngx_strncasecmp(p, (u_char *)".htdigest", 9) == 0))
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "htaccess: blocked access to \"%V\"", &r->uri);
                return NGX_HTTP_FORBIDDEN;
            }
        }
    }

    mc  = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->root.len == 0) return NGX_DECLINED;

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL) return NGX_DECLINED;

    /* first pass: collect all parsed files for ErrorDocument lookup */
    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h;

        h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL) continue;
        if (nparsed < HTA_MAX_DEPTH) parsed_list[nparsed++] = h;

        rc = hta_check_ssl(r, h);
        if (rc != NGX_OK) goto check_errdoc;

        /* Satisfy semantics:
         *   All (default): access AND auth must both pass
         *   Any:           either one is sufficient. Only run auth if access
         *                  denied; that way we don't push a stale
         *                  WWW-Authenticate header onto a request that
         *                  already passed by IP. */
        if (h->satisfy == HTA_SATISFY_ANY) {
            ngx_int_t rc_access = hta_check_access(r, h);
            if (rc_access == NGX_OK) {
                /* access OK, skip auth entirely */
            } else {
                rc = hta_check_auth(r, h);
                if (rc != NGX_OK) goto check_errdoc;
            }
        } else {
            rc = hta_check_access(r, h);
            if (rc != NGX_OK) goto check_errdoc;

            rc = hta_check_auth(r, h);
            if (rc != NGX_OK) goto check_errdoc;
        }

        /* <Files>/<FilesMatch> block access */
        rc = hta_check_files_access(r, h);
        if (rc != NGX_OK) goto check_errdoc;

        rc = hta_check_files_auth(r, h);
        if (rc != NGX_OK) goto check_errdoc;

        /* <Limit>/<LimitExcept> block access + auth */
        rc = hta_check_limit_access(r, h);
        if (rc != NGX_OK) goto check_errdoc;

        rc = hta_check_limit_auth(r, h);
        if (rc != NGX_OK) goto check_errdoc;
    }

    return NGX_DECLINED;

check_errdoc:
    /* check ErrorDocument for the error status */
    for (i = 0; i < nparsed; i++) {
        ngx_int_t erc;

        erc = hta_check_errdoc(r, parsed_list[i], rc);
        if (erc != rc) return erc;
    }
    return rc;
}
