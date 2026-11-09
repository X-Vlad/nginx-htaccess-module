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
#include <sys/stat.h>
#include <unistd.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * Mirror of ngx_http_index_module's per-location config so "Options -Indexes"
 * enforcement can consult nginx's ACTUAL `index` directive list (including a
 * custom `index home.html;`) instead of guessing filenames. This struct is not
 * exported in a public header, but it has been ABI-stable for many releases and
 * a dynamic module is always built against the exact nginx version it loads
 * into, so the layout is guaranteed to match at build time.
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    ngx_array_t *indices;       /* array of hta_index_elt_t */
    size_t       max_index_len;
} hta_index_loc_conf_t;

typedef struct {
    ngx_str_t    name;
    ngx_array_t *lengths;       /* non-NULL when the index name is scripted */
    ngx_array_t *values;
} hta_index_elt_t;

extern ngx_module_t ngx_http_index_module;


/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t hta_preconfigure(ngx_conf_t *cf);
static ngx_int_t hta_postconfigure(ngx_conf_t *cf);
static ngx_int_t hta_init_process(ngx_cycle_t *cycle);
static void      hta_exit_process(ngx_cycle_t *cycle);
static void     *hta_create_main(ngx_conf_t *cf);
static void     *hta_create_loc(ngx_conf_t *cf);
static char     *hta_conf_env_allow(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char     *hta_merge_loc(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t hta_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t hta_preaccess_handler(ngx_http_request_t *r);
static ngx_int_t hta_access_handler(ngx_http_request_t *r);
static ngx_int_t hta_rewrite_entry(ngx_http_request_t *r);
static ngx_int_t hta_preaccess_entry(ngx_http_request_t *r);
static ngx_int_t hta_access_entry(ngx_http_request_t *r);
static ngx_int_t hta_header_entry(ngx_http_request_t *r);

static ngx_int_t
hta_is_ht_basename(u_char *data, size_t len)
{
    u_char *p = data + len;

    while (p > data && p[-1] != '/') p--;

    return ((size_t) (data + len - p) >= 3
            && p[0] == '.'
            && (p[1] == 'h' || p[1] == 'H')
            && (p[2] == 't' || p[2] == 'T'));
}

static ngx_int_t hta_var_php_value(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t is_admin);

/*
 * The module resolves .htaccess paths from clcf->root directly.  A root or
 * alias with nginx variables requires root_lengths/root_values and cannot be
 * resolved this way; silently finding no .htaccess would disable all access
 * control, so fail closed instead.
 */
ngx_int_t
hta_location_supported(ngx_http_core_loc_conf_t *clcf)
{
    if (clcf->root.len == 0 || clcf->root.len >= HTA_MAX_PATH) return 0;

    if (clcf->alias == NGX_MAX_SIZE_T_VALUE) return 0;

    if (ngx_strlchr(clcf->root.data,
                    clcf->root.data + clcf->root.len, '$') != NULL)
    {
        return 0;
    }

    return 1;
}


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

    /* fail closed (500) when a .htaccess uses an unrecognized directive */
    { ngx_string("htaccess_strict"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, strict),
      NULL },

    /* trust X-Forwarded-Proto for SSLRequireSSL (nginx behind a TLS proxy) */
    { ngx_string("htaccess_trust_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, trust_proxy),
      NULL },

    /* require .htaccess/.htpasswd/.htgroup to be owned by the directory
     * owner (defeats symlink/hardlink cross-tenant reads) */
    { ngx_string("htaccess_owner_check"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, owner_check),
      NULL },

    /* php_admin_* from .htaccess is disabled by default: in shared hosting
     * it is a privilege-escalation primitive (open_basedir, disable_functions,
     * auto_prepend_file, ...). */
    { ngx_string("htaccess_allow_php_admin"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, allow_php_admin),
      NULL },

    { ngx_string("htaccess_allow_proxy_headers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, allow_proxy_headers),
      NULL },

    /* auto_prepend_file/open_basedir/... from a customer .htaccess can
     * escape the site or persist in a shared PHP-FPM worker. */
    { ngx_string("htaccess_allow_dangerous_php"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, allow_dangerous_php),
      NULL },

    /* Refuse "Header unset" of security headers set by a parent scope
     * unless the operator explicitly allows it. */
    { ngx_string("htaccess_allow_security_unset"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, allow_security_unset),
      NULL },

    /* Block request paths whose realpath escapes the document root through
     * a symlink (cross-tenant isolation).  Symlinks that stay inside the
     * root are still allowed. */
    { ngx_string("htaccess_symlink_check"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, symlink_check),
      NULL },

    /* Variables SetEnv/SetEnvIf/UnsetEnv/BrowserMatch may write: names, or
     * prefixes ending in "*"; "*" alone allows every changeable variable
     * (single-tenant setups).  Default: none, because an operator's own
     * "set $var" (limit_conn/limit_req keys, flags in if/map) would
     * otherwise be under every customer's control. */
    { ngx_string("htaccess_env_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      hta_conf_env_allow,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hta_loc_conf_t, env_allow),
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
    conf->strict = NGX_CONF_UNSET;
    conf->trust_proxy = NGX_CONF_UNSET;
    conf->owner_check = NGX_CONF_UNSET;
    conf->allow_php_admin = NGX_CONF_UNSET;
    conf->allow_proxy_headers = NGX_CONF_UNSET;
    conf->allow_dangerous_php = NGX_CONF_UNSET;
    conf->allow_security_unset = NGX_CONF_UNSET;
    conf->symlink_check = NGX_CONF_UNSET;
    conf->env_allow = NGX_CONF_UNSET_PTR;
    return conf;
}

/* htaccess_env_allow name ...;  every argument is one name or prefix* */
static char *
hta_conf_env_allow(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_hta_loc_conf_t  *lcf = conf;
    ngx_str_t                *value, *s;
    ngx_uint_t                i;

    if (lcf->env_allow == NGX_CONF_UNSET_PTR || lcf->env_allow == NULL) {
        lcf->env_allow = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t));
        if (lcf->env_allow == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            return "takes non-empty names";
        }
        s = ngx_array_push(lcf->env_allow);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


static char *
hta_merge_loc(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hta_loc_conf_t *prev = parent;
    ngx_http_hta_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->filename, prev->filename, ".htaccess");
    /*
     * Fail closed by default.  A typo or an unsupported security directive
     * must not silently turn into "no access control".  Operators can set
     * htaccess_strict off explicitly for compatibility.
     */
    ngx_conf_merge_value(conf->strict, prev->strict, 1);
    ngx_conf_merge_value(conf->trust_proxy, prev->trust_proxy, 0);
    ngx_conf_merge_value(conf->owner_check, prev->owner_check, 1);
    ngx_conf_merge_value(conf->allow_php_admin, prev->allow_php_admin, 0);
    ngx_conf_merge_value(conf->allow_proxy_headers,
                         prev->allow_proxy_headers, 0);
    ngx_conf_merge_value(conf->allow_dangerous_php,
                         prev->allow_dangerous_php, 0);
    ngx_conf_merge_value(conf->allow_security_unset,
                         prev->allow_security_unset, 0);
    ngx_conf_merge_value(conf->symlink_check, prev->symlink_check, 1);
    ngx_conf_merge_ptr_value(conf->env_allow, prev->env_allow, NULL);
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
    *h = hta_rewrite_entry;

    /* preaccess phase - re-apply SetEnvIf/SetEnv so its values stick AFTER
     * any `set $foo "";` in the location's rewrite script (nginx reverses
     * REWRITE_PHASE handler order, so our handler there runs BEFORE `set`). */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = hta_preaccess_entry;

    /* access phase - access control & auth */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = hta_access_entry;

    /* header filter - response headers, expires, content-type */
    hta_header_filter_init(ngx_http_top_header_filter);
    ngx_http_top_header_filter = hta_header_entry;

    return NGX_OK;
}


/*
 * Entry points: charge customer regexes to the request (hta_regex_enter) and
 * turn internal errors into 500.  A phase handler that returns NGX_ERROR
 * makes nginx drop the connection without an answer or a log line; a
 * regex over its budget must fail closed visibly instead.
 */

static ngx_int_t
hta_phase_result(ngx_int_t rc)
{
    return rc == NGX_ERROR ? NGX_HTTP_INTERNAL_SERVER_ERROR : rc;
}


static ngx_int_t
hta_rewrite_entry(ngx_http_request_t *r)
{
    ngx_http_request_t *prev = hta_regex_enter(r);
    ngx_int_t           rc = hta_rewrite_handler(r);

    hta_regex_leave(prev);
    return hta_phase_result(rc);
}


static ngx_int_t
hta_preaccess_entry(ngx_http_request_t *r)
{
    ngx_http_request_t *prev = hta_regex_enter(r);
    ngx_int_t           rc = hta_preaccess_handler(r);

    hta_regex_leave(prev);
    return hta_phase_result(rc);
}


static ngx_int_t
hta_access_entry(ngx_http_request_t *r)
{
    ngx_http_request_t *prev = hta_regex_enter(r);
    ngx_int_t           rc = hta_access_handler(r);

    hta_regex_leave(prev);
    return hta_phase_result(rc);
}


static ngx_int_t
hta_header_entry(ngx_http_request_t *r)
{
    ngx_http_request_t *prev = hta_regex_enter(r);
    ngx_int_t           rc = hta_header_filter(r);

    hta_regex_leave(prev);
    return rc;
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

    /* cleanup passwd cache pools */
    for (i = 0; i < conf->npasswd; i++) {
        if (conf->passwd[i].pool) {
            ngx_destroy_pool(conf->passwd[i].pool);
            conf->passwd[i].pool = NULL;
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Owner check for security-sensitive files.  O_NOFOLLOW blocks symlinks;
 * this blocks a hardlinked/foreign-owned file in a customer directory too.
 * ═══════════════════════════════════════════════════════════════════════ */

static ngx_int_t
hta_parent_uid(u_char *path, uid_t *uid)
{
    struct stat  pst;
    u_char       parent[HTA_MAX_PATH];
    u_char      *slash;
    size_t       len;

    len = ngx_strlen(path);
    if (len == 0 || len >= sizeof(parent)) return NGX_ERROR;

    ngx_memcpy(parent, path, len + 1);
    slash = (u_char *) strrchr((char *) parent, '/');
    if (slash == NULL) return NGX_ERROR;

    if (slash == parent) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }

    if (lstat((char *) parent, &pst) != 0) return NGX_ERROR;

    *uid = pst.st_uid;
    return NGX_OK;
}

ngx_int_t
hta_file_owner_ok(u_char *path, ngx_log_t *log)
{
    struct stat  st;
    uid_t        owner;

    if (lstat((char *) path, &st) != 0) return 0;
    if (hta_parent_uid(path, &owner) != NGX_OK) return 0;

    if (st.st_uid != owner) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "htaccess: owner mismatch for \"%s\", failing closed", path);
        return 0;
    }
    return 1;
}

ngx_int_t
hta_fd_owner_ok(ngx_fd_t fd, u_char *path, ngx_log_t *log)
{
    struct stat  st;
    uid_t        owner;

    if (fstat(fd, &st) != 0) return 0;
    if (hta_parent_uid(path, &owner) != NGX_OK) return 0;

    if (st.st_uid != owner) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "htaccess: owner mismatch for \"%s\", failing closed", path);
        return 0;
    }
    return 1;
}

ngx_int_t
hta_fd_uid_ok(ngx_fd_t fd, uid_t expected_uid, u_char *path, ngx_log_t *log)
{
    struct stat  st;

    if (fstat(fd, &st) != 0) return 0;

    if (st.st_uid != expected_uid) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "htaccess: auth file \"%s\" belongs to another tenant, "
            "failing closed", path);
        return 0;
    }
    return 1;
}


/*
 * Returns 1 when the request maps to a path whose realpath is inside the
 * document root, or when nothing exists at the path (normal 404).  Returns 0
 * on a symlink escape (cross-tenant read) and on mapping/confinement errors.
 */
ngx_int_t
hta_request_path_inside_root(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t *clcf;
    hta_req_ctx_t            *ctx;
    ngx_str_t                 path;
    size_t                    rl;
    u_char                   *last;
    char                      resolved[HTA_MAX_PATH];
    size_t                    rlen, n;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL || clcf->root.len == 0
        || clcf->root.len >= HTA_MAX_PATH)
    {
        return 0;
    }

    ctx = hta_req_ctx(r);
    if (ctx == NULL) return 0;

    {
        ngx_str_t rr;
        if (hta_root_real(r, &rr) != NGX_OK) return 0;
    }

    last = ngx_http_map_uri_to_path(r, &path, &rl, 0);
    if (last == NULL) return 0;

    *last = '\0';

    if (realpath((char *) path.data, resolved) == NULL) {
        /* does not exist: the static handler will 404 */
        return 1;
    }

    n = ngx_strlen(resolved);
    rlen = ctx->root_real.len;

    if (rlen == 1 && ctx->root_real.data[0] == '/') {
        return 1;
    }
    if (n < rlen || ngx_memcmp(resolved, ctx->root_real.data, rlen) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "htaccess: request path escapes document root, denying");
        return 0;
    }
    return (n == rlen || resolved[rlen] == '/');
}


/*
 * realpath() of the location's document root, once per request (it was
 * resolved again for every file test and auth file).
 */
ngx_int_t
hta_root_real(ngx_http_request_t *r, ngx_str_t *out)
{
    ngx_http_core_loc_conf_t *clcf;
    hta_req_ctx_t            *ctx;
    char                      resolved[PATH_MAX];
    size_t                    rlen;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL || clcf->root.len == 0
        || clcf->root.len >= HTA_MAX_PATH)
    {
        return NGX_ERROR;
    }

    ctx = hta_req_ctx(r);
    if (ctx == NULL) return NGX_ERROR;

    /* an internal rewrite can move the request to a location with another
     * root: resolve again then, never compare against a stale root */
    if (!ctx->root_real_set || ctx->root_conf != clcf->root.data) {
        ctx->root_real_set = 0;
        if (realpath((char *) clcf->root.data, resolved) == NULL) {
            return NGX_ERROR;
        }
        ctx->root_conf = clcf->root.data;
        /* the old root fd stays open until its pool cleanup runs */
        ctx->root_fd_set = 0;
        rlen = ngx_strlen(resolved);
        ctx->root_real.data = ngx_pnalloc(r->pool, rlen + 1);
        if (ctx->root_real.data == NULL) return NGX_ERROR;
        ngx_memcpy(ctx->root_real.data, resolved, rlen + 1);
        ctx->root_real.len = rlen;
        ctx->root_real_set = 1;
    }

    *out = ctx->root_real;
    return NGX_OK;
}


/*
 * Options -FollowSymLinks: return 1 if any component below the document root
 * is a symlink.  The root itself may legitimately be a symlink.
 */
ngx_int_t
hta_path_has_symlink(ngx_http_request_t *r)
{
    ngx_str_t       path;
    size_t          rl;
    u_char         *last, *p, *seg, *end;
    u_char          cur[HTA_MAX_PATH];
    size_t          clen;
    struct stat     st;

    last = ngx_http_map_uri_to_path(r, &path, &rl, 0);
    if (last == NULL) return 1;

    *last = '\0';
    end = last;

    if (rl >= sizeof(cur)) return 1;
    ngx_memcpy(cur, path.data, rl);
    clen = rl;

    p = path.data + rl;
    while (p < end) {
        while (p < end && *p == '/') p++;
        if (p >= end) break;

        seg = p;
        while (p < end && *p != '/') p++;

        if (clen + 1 + (size_t) (p - seg) >= sizeof(cur)) return 1;
        cur[clen++] = '/';
        ngx_memcpy(cur + clen, seg, p - seg);
        clen += p - seg;
        cur[clen] = '\0';

        if (lstat((char *) cur, &st) != 0) {
            return 0;  /* missing: normal 404 */
        }
        if (S_ISLNK(st.st_mode)) {
            return 1;
        }
    }

    return 0;
}


/*
 * Copy a value out of a cached hta_parsed_t pool into the request pool.
 * Every pointer that survives the current handler (headers_in/out, r->uri,
 * SetEnv values, ErrorDocument targets) must go through this: cache
 * eviction/inotify invalidation destroys parsed pools while other requests
 * may still hold those pointers.
 */
ngx_int_t
hta_pstrdup(ngx_http_request_t *r, ngx_str_t *dst, const ngx_str_t *src)
{
    if (src->len == 0) {
        dst->data = (u_char *) "";
        dst->len  = 0;
        return NGX_OK;
    }

    /*
     * Always NUL-terminate: copies of paths (an inherited AuthUserFile, file
     * names) reach stat()/open()/realpath() as C strings.  ngx_pstrdup()
     * copies exactly len bytes, so the byte after the copy belonged to the
     * next pool allocation: the path read on into it, and the auth file was
     * found or not depending on what had been allocated next.
     */
    dst->data = ngx_pnalloc(r->pool, src->len + 1);
    if (dst->data == NULL) {
        dst->len = 0;
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;
    return NGX_OK;
}


/* Apache <Files> wildcard matching: '*' and '?', case-sensitive on Unix. */
ngx_int_t
hta_wildcard_match(u_char *pattern, size_t plen, u_char *name, size_t nlen)
{
    size_t pi = 0, ni = 0, star = (size_t) -1, mark = 0;

    while (ni < nlen) {
        if (pi < plen && (pattern[pi] == '?' || pattern[pi] == name[ni])) {
            pi++;
            ni++;
        } else if (pi < plen && pattern[pi] == '*') {
            star = pi++;
            mark = ni;
        } else if (star != (size_t) -1) {
            pi = star + 1;
            ni = ++mark;
        } else {
            return 0;
        }
    }

    while (pi < plen && pattern[pi] == '*') {
        pi++;
    }

    return pi == plen;
}


/* PHP settings that can escape the site / cross tenant boundaries. */
static const char *hta_dangerous_php_names[] = {
    "auto_prepend_file", "auto_append_file", "open_basedir",
    "disable_functions", "disable_classes", "extension", "zend_extension",
    "include_path", "error_log", "session.save_path", "upload_tmp_dir",
    "sys_temp_dir", "allow_url_include", "allow_url_fopen", "mail.log",
    "soap.wsdl_cache_dir", "opcache.preload", "ffi.enable",
    "mail.force_extra_parameters", "sendmail_path", "user_ini.filename",
    "opcache.file_cache", "opcache.restrict_api", NULL
};

ngx_int_t
hta_dangerous_php_value(ngx_str_t *name)
{
    ngx_uint_t i;

    for (i = 0; hta_dangerous_php_names[i]; i++) {
        size_t len = ngx_strlen(hta_dangerous_php_names[i]);
        if (name->len == len
            && ngx_strncasecmp(name->data, (u_char *) hta_dangerous_php_names[i],
                               len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/* Response headers that protect the browser; a child .htaccess must not
 * silently remove them (parent scope may set them). */
static const char *hta_security_header_names[] = {
    "strict-transport-security", "content-security-policy",
    "content-security-policy-report-only", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "cross-origin-resource-policy", "x-xss-protection",
    "x-permitted-cross-domain-policies", NULL
};

ngx_int_t
hta_protected_security_header(ngx_str_t *name)
{
    ngx_uint_t i;

    for (i = 0; hta_security_header_names[i]; i++) {
        size_t len = ngx_strlen(hta_security_header_names[i]);
        if (name->len == len
            && ngx_strncasecmp(name->data,
                               (u_char *) hta_security_header_names[i],
                               len) == 0)
        {
            return 1;
        }
    }
    return 0;
}



/* ═══════════════════════════════════════════════════════════════════════════
 * Directory traversal - find all .htaccess files from root to deepest dir
 * ═══════════════════════════════════════════════════════════════════════ */

/*
 * Is there a .htaccess entry at path?  lstat(), not stat(): a symlinked
 * .htaccess whose target nginx cannot reach (another tenant's home) made
 * stat() fail and the file was skipped, so its rules silently did not
 * apply; now it is collected and refused at open (O_NOFOLLOW, 500).  Any
 * error other than "does not exist" fails the request closed.
 */
static ngx_int_t
hta_ht_present(u_char *path, hta_file_list_t *list)
{
    struct stat st;

    if (lstat((char *) path, &st) == 0) {
        return 1;
    }
    if (errno != ENOENT && errno != ENOTDIR) {
        list->error = 1;
    }
    return 0;
}


void
hta_collect_files(ngx_http_request_t *r, ngx_str_t *root, ngx_str_t *filename,
    hta_file_list_t *list)
{
    u_char          path[HTA_MAX_PATH];
    ngx_int_t       plen;
    u_char         *uri_p, *uri_end;
    u_char          dir[HTA_MAX_PATH];
    ngx_int_t       dlen;

    list->count = 0;
    list->error = 0;

    if (root->len == 0 || root->len >= sizeof(dir) - 1
        || filename->len >= sizeof(path))
    {
        list->error = 1;
        return;
    }

    /* document root .htaccess */
    if (root->len + 1 + filename->len >= sizeof(path)) {
        list->error = 1;
        return;
    }

    plen = (ngx_int_t) (ngx_cpymem(path, root->data, root->len) - path);
    path[plen++] = '/';
    plen += (ngx_int_t) (ngx_cpymem(path + plen, filename->data,
                                    filename->len) - (path + plen));
    path[plen] = '\0';

    if (hta_ht_present(path, list)) {
        list->files[list->count].data = ngx_pnalloc(r->pool, plen + 1);
        if (list->files[list->count].data == NULL) {
            list->error = 1;
            return;
        }
        ngx_memcpy(list->files[list->count].data, path, plen + 1);
        list->files[list->count].len = plen;
        list->count++;
    }

    dlen = (ngx_int_t) root->len;
    ngx_memcpy(dir, root->data, dlen);
    dir[dlen] = '\0';

    /*
     * For `alias` locations, the leading part of r->uri that matches the
     * location prefix is replaced by `root` on disk (see
     * ngx_http_map_uri_to_path). Skip those bytes so paths resolve under the
     * alias target instead of doubling the prefix.
     */
    {
        ngx_http_core_loc_conf_t *clcf;
        size_t                    alias_off = 0;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        if (clcf->alias != 0 && clcf->alias != NGX_MAX_SIZE_T_VALUE
            && clcf->alias <= r->uri.len)
        {
            alias_off = clcf->alias;
        }
        uri_p = r->uri.data + alias_off;
    }
    uri_end = r->uri.data + r->uri.len;
    if (uri_p < uri_end && *uri_p == '/') uri_p++;

    while (uri_p < uri_end) {
        u_char     *seg;
        ngx_uint_t  slen;

        seg = uri_p;
        while (uri_p < uri_end && *uri_p != '/') uri_p++;
        if (uri_p >= uri_end) break;  /* last segment is file, not dir */

        slen = uri_p - seg;

        /*
         * A dot-dot segment means the URI was not normalized as expected.
         * Treat it as a hard error instead of guessing which directory the
         * static handler will actually use (that mismatch is an isolation
         * bypass class).
         */
        if ((slen == 2 && seg[0] == '.' && seg[1] == '.')
            || (slen == 1 && seg[0] == '.'))
        {
            list->error = 1;
            return;
        }
        /* skip empty segments ("//") */
        if (slen == 0) {
            uri_p++;
            continue;
        }

        if (list->count >= HTA_MAX_DEPTH) {
            list->error = 1;
            return;
        }

        if (dlen + 1 + (ngx_int_t) slen >= (ngx_int_t) sizeof(dir) - 1) {
            list->error = 1;
            return;
        }

        dir[dlen] = '/';
        ngx_memcpy(dir + dlen + 1, seg, slen);
        dlen += 1 + slen;
        dir[dlen] = '\0';

        plen = ngx_snprintf(path, sizeof(path), "%s/%V", dir, filename) - path;
        if (plen < 0 || plen >= (ngx_int_t) sizeof(path) - 1) {
            list->error = 1;
            return;
        }
        path[plen] = '\0';

        if (hta_ht_present(path, list)) {
            list->files[list->count].data = ngx_pnalloc(r->pool, plen + 1);
            if (list->files[list->count].data == NULL) {
                list->error = 1;
                return;
            }
            ngx_memcpy(list->files[list->count].data, path, plen + 1);
            list->files[list->count].len = plen;
            list->count++;
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

typedef struct {
    ngx_str_t name;
    ngx_str_t value;
} hta_php_copy_t;

static ngx_int_t hta_var_php_value_get(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t is_admin);

static ngx_int_t
hta_var_php_value(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t is_admin)
{
    ngx_http_request_t *prev = hta_regex_enter(r);
    ngx_int_t           rc = hta_var_php_value_get(r, v, is_admin);

    hta_regex_leave(prev);
    return rc;
}


static ngx_int_t
hta_var_php_value_get(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t is_admin)
{
    ngx_http_hta_loc_conf_t   *lcf;
    ngx_http_hta_main_conf_t  *mc;
    ngx_http_core_loc_conf_t  *clcf;
    hta_file_list_t           *files;
    ngx_array_t               *vals;
    hta_php_copy_t            *copy;
    ngx_uint_t                 i, j;
    size_t                     total = 0;
    u_char                    *buf, *p;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = 0;
    v->data = (u_char *) "";

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (lcf == NULL || !lcf->enable) return NGX_OK;

    /* php_admin_* from a customer .htaccess is privilege escalation. */
    if (is_admin && !lcf->allow_php_admin) {
        return NGX_OK;
    }

    mc = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (mc == NULL || clcf == NULL) return NGX_ERROR;
    if (!hta_location_supported(clcf)) return NGX_ERROR;

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL || files->error) return NGX_ERROR;
    if (files->count == 0) return NGX_OK;

    vals = ngx_array_create(r->pool, 16, sizeof(hta_php_copy_t));
    if (vals == NULL) return NGX_ERROR;

    /* first pass: copy values out of the cache pool and total output size */
    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL || h->invalid || (lcf->strict && h->has_unknown)) {
            return NGX_ERROR;
        }

        for (j = 0; j < h->nphp_values; j++) {
            hta_php_value_t *pv = &h->php_values[j];
            if ((pv->is_admin ? 1u : 0u) != (ngx_uint_t) is_admin) continue;

            if (!lcf->allow_dangerous_php
                && hta_dangerous_php_value(&pv->name))
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                    "htaccess: refusing dangerous PHP setting \"%V\" "
                    "(htaccess_allow_dangerous_php is off)", &pv->name);
                continue;
            }

            copy = ngx_array_push(vals);
            if (copy == NULL) return NGX_ERROR;
            if (hta_pstrdup(r, &copy->name, &pv->name) != NGX_OK
                || hta_pstrdup(r, &copy->value, &pv->value) != NGX_OK)
            {
                return NGX_ERROR;
            }
            total += copy->name.len + 1 + copy->value.len + 1;
        }
    }
    if (total == 0) return NGX_OK;

    buf = ngx_pnalloc(r->pool, total);
    if (buf == NULL) return NGX_ERROR;
    p = buf;

    copy = vals->elts;
    for (i = 0; i < vals->nelts; i++) {
        p = ngx_cpymem(p, copy[i].name.data, copy[i].name.len);
        *p++ = '=';
        p = ngx_cpymem(p, copy[i].value.data, copy[i].value.len);
        *p++ = '\n';
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

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return NGX_DECLINED;

    mc  = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!hta_location_supported(clcf)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "htaccess: unsupported variable root/alias, failing closed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Read pending inotify events on every request.  The old "every 64
     * requests" amortisation meant a new deny/auth rule could be ignored by
     * up to 63 requests; on a quiet site that is an unbounded security
     * window.  read() on a non-blocking empty inotify fd only costs EAGAIN.
     */
    hta_inotify_poll(mc, r->connection->log);

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL || files->error) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
    ngx_str_t fallback = ngx_null_string;

    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h;

        h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL || h->invalid
            || (lcf->strict && h->has_unknown))
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* deepest FallbackResource wins (files walk root -> leaf) */
        if (h->fallback_resource.len) {
            if (hta_pstrdup(r, &fallback, &h->fallback_resource) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        /* apply SetEnvIf early (before rewrite rules) */
        if (hta_apply_setenvif(r, h) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* mutate request headers before upstream phases see them */
        hta_apply_request_headers(r, h);

        rc = hta_apply_dirindex(r, h);
        if (rc != NGX_DECLINED) return rc;

        rc = hta_apply_redirects(r, h);
        if (rc != NGX_DECLINED) return rc;

        rc = hta_apply_rules(r, h);
        if (rc != NGX_DECLINED) return rc;
    }

    /* FallbackResource: no rule matched and the file is absent -> front
     * controller. Runs last so real files / explicit rewrites win. */
    if (fallback.len) {
        rc = hta_apply_fallback(r, &fallback);
        if (rc != NGX_DECLINED) return rc;
    }
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

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return NGX_DECLINED;

    /*
     * nginx's core access phase skips subrequests entirely.  Run the
     * module's access/auth checks here for subrequests so SSI includes and
     * auth_request probes cannot bypass a site's .htaccess policy.
     */
    if (r != r->main) {
        ngx_int_t rc = hta_access_handler(r);
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    mc   = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!hta_location_supported(clcf)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "htaccess: unsupported variable root/alias, failing closed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL || files->error) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL || h->invalid || (lcf->strict && h->has_unknown)) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (hta_apply_setenvif(r, h) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    hta_apply_late_env(r);

    return NGX_DECLINED;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Access phase handler - entry point
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    unsigned  valid:1;
    unsigned  basic:1;
    unsigned  unsupported:1;
    ngx_str_t name;
    ngx_str_t user_file;
    ngx_str_t group_file;
} hta_auth_inherit_t;

static ngx_int_t
hta_access_handler(ngx_http_request_t *r)
{
    ngx_http_hta_loc_conf_t   *lcf;
    ngx_http_hta_main_conf_t  *mc;
    ngx_http_core_loc_conf_t  *clcf;
    hta_file_list_t           *files;
    ngx_uint_t                 i, j;
    ngx_int_t                  rc;
    hta_errdoc_t               errdocs[HTA_MAX_DEPTH * HTA_MAX_ERRDOCS];
    ngx_uint_t                 nerrdocs = 0;
    unsigned                   saw_opt = 0;
    int                        indexes = 1;
    int                        follow_sym = 1;
    unsigned                   found_index = 0;
    ngx_str_t                  dpath;
    size_t                     root_len = 0;
    u_char                    *index_last = NULL;
    ngx_file_info_t            fi;
    hta_auth_inherit_t         auth_state;
    hta_parsed_t              *auth_eff = NULL;

    ngx_memzero(&auth_state, sizeof(auth_state));

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);
    if (!lcf->enable) return NGX_DECLINED;

    /* Security: block direct access to .htaccess, .htpasswd and similar. */
    if (hta_is_ht_basename(r->uri.data, r->uri.len)) {
        /* Block ANY file whose basename starts with ".ht" (Apache's stock
         * "<FilesMatch ^\.ht>" convention). This covers not only
         * .htaccess/.htpasswd/.htgroup/.htdigest but also editor backups
         * like .htpasswd.bak, .htaccess~, .htaccess.save and swap files,
         * which would otherwise be served in cleartext. */
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "htaccess: blocked access to \"%V\"", &r->uri);
        return NGX_HTTP_FORBIDDEN;
    }

    mc  = ngx_http_get_module_main_conf(r, ngx_http_htaccess_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!hta_location_supported(clcf)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "htaccess: unsupported variable root/alias, failing closed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Cross-tenant isolation: a symlink inside a customer directory must not
     * make nginx serve a file from another customer's tree.  Symlinks that
     * resolve inside the document root are still allowed.
     */
    if (lcf->symlink_check && !hta_request_path_inside_root(r)) {
        return NGX_HTTP_FORBIDDEN;
    }

    files = hta_get_files(r, &clcf->root, &lcf->filename);
    if (files == NULL || files->error) return NGX_HTTP_INTERNAL_SERVER_ERROR;

    /*
     * Pass 1: parse every file and collect ErrorDocument entries before any
     * access check can jump to check_errdoc.  Otherwise a parent "Require all
     * denied" would fire before the child's ErrorDocument was seen, and the
     * parent document would win (wrong precedence).
     */
    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h = hta_get_parsed(r, mc, &files->files[i]);

        if (h == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        if (h->invalid) continue;

        for (j = 0; j < h->nerrdocs; j++) {
            if (nerrdocs >= HTA_MAX_DEPTH * HTA_MAX_ERRDOCS) break;
            errdocs[nerrdocs] = h->errdocs[j];
            if (hta_pstrdup(r, &errdocs[nerrdocs].response,
                            &h->errdocs[j].response) != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            nerrdocs++;
        }

        if (h->has_opts) {
            if (h->opts_set & HTA_OPT_INDEXES)   { indexes = 1; saw_opt = 1; }
            if (h->opts_unset & HTA_OPT_INDEXES) { indexes = 0; saw_opt = 1; }
            if (h->opts_set & HTA_OPT_FOLLOWSYM)   { follow_sym = 1; saw_opt = 1; }
            if (h->opts_unset & HTA_OPT_FOLLOWSYM) { follow_sym = 0; saw_opt = 1; }
        }

        if (r->uri.len > 0 && r->uri.data[r->uri.len - 1] == '/'
            && h->nindex > 0)
        {
            if (index_last == NULL) {
                index_last = ngx_http_map_uri_to_path(r, &dpath, &root_len, 256);
            }
            if (index_last != NULL) {
                ngx_uint_t k;
                for (k = 0; k < h->nindex; k++) {
                    u_char *e;
                    if (h->index_files[k].len >= 255) continue;
                    e = ngx_cpymem(index_last, h->index_files[k].data,
                                   h->index_files[k].len);
                    *e = '\0';
                    if (ngx_file_info(dpath.data, &fi) == 0
                        && ngx_is_file(&fi))
                    {
                        found_index = 1;
                        break;
                    }
                }
            }
        }
    }

    /* Pass 2: access/auth/exec checks, root -> leaf. */
    for (i = 0; i < files->count; i++) {
        hta_parsed_t *h;

        h = hta_get_parsed(r, mc, &files->files[i]);
        if (h == NULL || h->invalid) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto check_errdoc;
        }

        /*
         * Apache auth configuration is inherited from the parent directory:
         * a child .htaccess may contain only "Require valid-user" and use the
         * AuthType/AuthUserFile from an ancestor.  Values that outlive the
         * current cache entry are copied into the request pool so a later
         * cache eviction cannot create a dangling pointer.
         */
        {
            hta_parsed_t *eff = h;

            if (auth_state.valid) {
                if (auth_eff == NULL) {
                    auth_eff = ngx_palloc(r->pool, sizeof(hta_parsed_t));
                    if (auth_eff == NULL) {
                        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                        goto check_errdoc;
                    }
                }
                eff = auth_eff;
                *eff = *h;

                if (!eff->auth_basic && !eff->auth_type_unsupported) {
                    eff->auth_basic            = auth_state.basic;
                    eff->auth_type_unsupported = auth_state.unsupported;
                }
                if (eff->auth_name.len == 0) {
                    eff->auth_name = auth_state.name;
                }
                if (eff->auth_user_file.len == 0) {
                    eff->auth_user_file = auth_state.user_file;
                }
                if (eff->auth_group_file.len == 0) {
                    eff->auth_group_file = auth_state.group_file;
                }
            }

            if (h->auth_basic || h->auth_type_unsupported) {
                auth_state.valid       = 1;
                auth_state.basic       = h->auth_basic;
                auth_state.unsupported = h->auth_type_unsupported;
            }
            if (h->auth_name.len) {
                if (hta_pstrdup(r, &auth_state.name, &h->auth_name)
                    != NGX_OK)
                {
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    goto check_errdoc;
                }
                auth_state.valid = 1;
            }
            if (h->auth_user_file.len) {
                if (hta_pstrdup(r, &auth_state.user_file, &h->auth_user_file)
                    != NGX_OK)
                {
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    goto check_errdoc;
                }
                auth_state.valid = 1;
            }
            if (h->auth_group_file.len) {
                if (hta_pstrdup(r, &auth_state.group_file,
                                &h->auth_group_file) != NGX_OK)
                {
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    goto check_errdoc;
                }
                auth_state.valid = 1;
            }

            h = eff;
        }

        /* Strict mode: an unrecognized directive is a hard error (Apache 500s)
         * rather than being silently dropped, which could otherwise turn a
         * misspelled security directive into no protection. */
        if (lcf->strict && h->has_unknown) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "htaccess: unknown directive in \"%V\" and htaccess_strict is "
                "on, denying", &files->files[i]);
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto check_errdoc;
        }

        rc = hta_check_ssl(r, h, lcf->trust_proxy);
        if (rc != NGX_OK) goto check_errdoc;

        /* Satisfy semantics:
         *   All (default): access AND auth must both pass
         *   Any:           either one is sufficient. Only run auth if access
         *                  denied; that way we don't push a stale
         *                  WWW-Authenticate header onto a request that
         *                  already passed by IP. */
        unsigned skip_auth = 0;
        unsigned has_scope_access = h->has_acl || h->has_require_host
                                    || h->require_local || h->require_granted
                                    || h->require_denied || h->require_failed;

        if (h->satisfy == HTA_SATISFY_ANY) {
            if (has_scope_access && hta_check_access(r, h) == NGX_OK) {
                /* access granted by a real access rule - "Any" is satisfied */
                skip_auth = 1;
            } else {
                /*
                 * No host rule is not an implicit "allow": with Satisfy Any
                 * and only AuthType/Require valid-user this used to skip auth
                 * completely.
                 */
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

        if (!skip_auth) {
            rc = hta_check_files_auth(r, h);
            if (rc != NGX_OK) goto check_errdoc;
        }

        /* <Limit>/<LimitExcept> block access + auth */
        rc = hta_check_limit_access(r, h);
        if (rc != NGX_OK) goto check_errdoc;

        if (!skip_auth) {
            rc = hta_check_limit_auth(r, h);
            if (rc != NGX_OK) goto check_errdoc;
        }

        /* SetHandler none / RemoveHandler .php / php_flag engine off:
         * block script execution (uploaded-shell protection) */
        rc = hta_check_exec(r, h);
        if (rc != NGX_OK) goto check_errdoc;
    }

    /* Options -FollowSymLinks: reject requests whose path below the document
     * root contains a symlink.  nginx's static handler follows symlinks
     * unconditionally; without this the option was silently ignored. */
    if (saw_opt && !follow_sym && hta_path_has_symlink(r)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "htaccess: Options -FollowSymLinks, refusing symlinked path "
            "\"%V\"", &r->uri);
        rc = NGX_HTTP_FORBIDDEN;
        goto check_errdoc;
    }

    /* Options -Indexes enforcement: refuse to list a directory that has no
     * index file. Without this the parsed opts were never consulted, so a
     * hardening "Options -Indexes" was a no-op and `autoindex on` would still
     * expose listings. Only fires when Options explicitly disabled Indexes and
     * the request is for a directory with no index file on disk. */
    if (r->uri.len > 0 && r->uri.data[r->uri.len - 1] == '/'
        && saw_opt && !indexes)
    {
        if (index_last == NULL) {
            index_last = ngx_http_map_uri_to_path(r, &dpath, &root_len, 256);
        }

        /*
         * nginx's own `index` directive list (covers the default index.html
         * and any custom names).  A scripted or absolute index name is
         * assumed servable so we never wrongly 403.
         */
        if (!found_index) {
#if (nginx_version >= 1024000 && nginx_version <= 1031999)
            hta_index_loc_conf_t *ilcf;
            ilcf = ngx_http_get_module_loc_conf(r, ngx_http_index_module);
            if (ilcf != NULL && ilcf->indices != NULL && index_last != NULL) {
                hta_index_elt_t *idx = ilcf->indices->elts;
                ngx_uint_t       k;
                for (k = 0; k < ilcf->indices->nelts && !found_index; k++) {
                    u_char *e;
                    if (idx[k].lengths != NULL) { found_index = 1; break; }
                    if (idx[k].name.len == 0 || idx[k].name.len >= 255)
                        continue;
                    if (idx[k].name.data[0] == '/') { found_index = 1; break; }
                    e = ngx_cpymem(index_last, idx[k].name.data,
                                   idx[k].name.len);
                    *e = '\0';
                    if (ngx_file_info(dpath.data, &fi) == 0
                        && ngx_is_file(&fi))
                        found_index = 1;
                }
            }
#else
            {
                static const char *defidx[] = {
                    "index.html", "index.htm", "index.php", NULL };
                ngx_uint_t di;
                for (di = 0; index_last != NULL && defidx[di] && !found_index;
                     di++)
                {
                    u_char *e = ngx_cpymem(index_last, defidx[di],
                                           ngx_strlen(defidx[di]));
                    *e = '\0';
                    if (ngx_file_info(dpath.data, &fi) == 0
                        && ngx_is_file(&fi))
                        found_index = 1;
                }
            }
#endif
        }

        if (!found_index) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "htaccess: Options -Indexes, refusing listing of \"%V\"",
                &r->uri);
            rc = NGX_HTTP_FORBIDDEN;
            goto check_errdoc;
        }
    }

    return NGX_DECLINED;

check_errdoc:
    /* check ErrorDocument for the error status */
    if (nerrdocs > 0) {
        ngx_int_t erc = hta_check_errdoc(r, errdocs, nerrdocs, rc);
        if (erc != rc) return erc;
    }
    return rc;
}
