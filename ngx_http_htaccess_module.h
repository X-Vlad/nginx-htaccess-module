/*
 * ngx_http_htaccess_module.h - Native .htaccess support for nginx
 * License: BSD-2-Clause
 */
#ifndef _NGX_HTTP_HTACCESS_MODULE_H_
#define _NGX_HTTP_HTACCESS_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════ */

#define HTA_MAX_PATH          4096
#define HTA_MAX_LINE          8192
#define HTA_MAX_RULES         256
#define HTA_MAX_CONDS         32
#define HTA_MAX_HEADERS       64
#define HTA_MAX_ERRDOCS       32
#define HTA_MAX_DEPTH         64
#define HTA_MAX_INDEX         16
#define HTA_MAX_USERS         64
#define HTA_MAX_ADDTYPES      64
#define HTA_MAX_EXPIRES       64
#define HTA_MAX_SETENVIF      32
#define HTA_MAX_REDIRECTS     64
#define HTA_MAX_FILES_BLOCKS  16
#define HTA_MAX_FB_ACL        16
#define HTA_MAX_FB_HEADERS    16
#define HTA_MAX_LIMIT_BLOCKS  8
#define HTA_MAX_LB_ACL        16
#define HTA_MAX_PHP_VALUES    32
#define HTA_MAX_GROUPS        16  /* Require group entries per scope */
#define HTA_MAX_REQ_HEADERS   32  /* RequestHeader actions */
#define HTA_CACHE_SLOTS       1024
#define HTA_PASSWD_SLOTS      256
#define HTA_INOTIFY_BUF       4096
#define HTA_MAX_CAPTURES      30
#define HTA_MAX_TOKENS        64
#define HTA_MAX_REGEX_LEN     4096
#define HTA_REGEX_MAX_BYTES   (8 * 1024 * 1024)

/*
 * CPU limits for customer regexes (shared hosting: one tenant must not be
 * able to occupy a worker that serves every other tenant).
 *   - per match: PCRE2 match and depth limits;
 *   - per request: total time and number of matches across every rule,
 *     condition, FilesMatch, SetEnvIf and RedirectMatch, after which the
 *     request fails closed with 500;
 *   - per file: number of compiled patterns (refused at parse time).
 * A request that walks every pattern of a maximal file at the per-match
 * limit stops after HTA_REGEX_BUDGET_MS instead of running for minutes.
 */
#define HTA_REGEX_MATCH_LIMIT 100000
#define HTA_REGEX_DEPTH_LIMIT 250
#define HTA_REGEX_BUDGET_MS   50
#define HTA_REGEX_MAX_EXEC    4096
#define HTA_MAX_REGEX_PER_FILE 1024
/* bytes all expansions of one request may allocate */
#define HTA_EXPAND_BUDGET     (4 * 1024 * 1024)
#define HTA_CACHE_MAX_BYTES   (64 * 1024 * 1024)
#define HTA_PASSWD_MAX_BYTES  (32 * 1024 * 1024)

/*
 * What identifies one version of a file when inotify is not available (NFS,
 * watch limits): mtime in seconds alone missed two edits within the same
 * second, so a deny rule added right after another change was never seen.
 */
typedef struct {
    time_t   mtime_sec;
    long     mtime_nsec;
    time_t   ctime_sec;
    long     ctime_nsec;
    ino_t    ino;
    dev_t    dev;
    off_t    size;
} hta_fver_t;

#define hta_fver_set(v, st)                                                   \
    do {                                                                      \
        (v)->mtime_sec = (st)->st_mtim.tv_sec;                                \
        (v)->mtime_nsec = (st)->st_mtim.tv_nsec;                              \
        (v)->ctime_sec = (st)->st_ctim.tv_sec;                                \
        (v)->ctime_nsec = (st)->st_ctim.tv_nsec;                              \
        (v)->ino = (st)->st_ino;                                              \
        (v)->dev = (st)->st_dev;                                              \
        (v)->size = (st)->st_size;                                            \
    } while (0)

#define hta_fver_eq(a, b)                                                     \
    ((a)->mtime_sec == (b)->mtime_sec && (a)->mtime_nsec == (b)->mtime_nsec  \
     && (a)->ctime_sec == (b)->ctime_sec && (a)->ctime_nsec == (b)->ctime_nsec \
     && (a)->ino == (b)->ino && (a)->dev == (b)->dev && (a)->size == (b)->size)

/* RewriteRule flags */
#define HTA_F_LAST            0x0001
#define HTA_F_REDIRECT        0x0002
#define HTA_F_FORBIDDEN       0x0004
#define HTA_F_GONE            0x0008
#define HTA_F_NOCASE          0x0010
#define HTA_F_NOESCAPE        0x0020
#define HTA_F_QSA             0x0040
#define HTA_F_QSD             0x0080
#define HTA_F_SKIP            0x0100
#define HTA_F_ENV             0x0200
#define HTA_F_CHAIN           0x0400
#define HTA_F_PT              0x0800
#define HTA_F_END             0x1000
#define HTA_F_NOT             0x2000

/* RewriteCond flags */
#define HTA_CF_NOCASE         0x0001
#define HTA_CF_OR             0x0002
#define HTA_CF_NEGATE         0x0004

/* Cond test types */
#define HTA_TEST_REGEX        0
#define HTA_TEST_FILE         1
#define HTA_TEST_DIR          2
#define HTA_TEST_LINK         3
#define HTA_TEST_EXISTS       4
#define HTA_TEST_SIZE         5
/* lexicographic string comparison (=, <, >, <=, >=) */
#define HTA_TEST_STR_EQ       6
#define HTA_TEST_STR_LT       7
#define HTA_TEST_STR_GT       8
#define HTA_TEST_STR_LE       9
#define HTA_TEST_STR_GE       10
/* integer comparison (-eq, -ne, -lt, -le, -gt, -ge) */
#define HTA_TEST_INT_EQ       11
#define HTA_TEST_INT_NE       12
#define HTA_TEST_INT_LT       13
#define HTA_TEST_INT_LE       14
#define HTA_TEST_INT_GT       15
#define HTA_TEST_INT_GE       16

/* Access order */
#define HTA_ORDER_DENY_ALLOW  0
#define HTA_ORDER_ALLOW_DENY  1

/* Options */
#define HTA_OPT_INDEXES       0x01
#define HTA_OPT_FOLLOWSYM     0x02
#define HTA_OPT_MULTIVIEWS    0x04

/* Header actions */
#define HTA_HDR_SET            0
#define HTA_HDR_UNSET          1
#define HTA_HDR_APPEND         2
#define HTA_HDR_ADD            3
#define HTA_HDR_MERGE          4

/* Satisfy directive */
#define HTA_SATISFY_ALL        0   /* default: both access and auth must pass */
#define HTA_SATISFY_ANY        1   /* either access OR auth is enough */


/* ═══════════════════════════════════════════════════════════════════════════
 * Structures
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    ngx_str_t    test_string;
    ngx_str_t    cond_pattern;
    ngx_regex_t *regex;
    ngx_uint_t   flags;
    ngx_uint_t   test_type;
} hta_cond_t;

typedef struct {
    ngx_str_t    pattern;
    ngx_str_t    substitution;
    ngx_regex_t *regex;
    ngx_uint_t   flags;
    ngx_int_t    redirect_code;
    ngx_int_t    skip_count;
    ngx_str_t    env_key;
    ngx_str_t    env_val;
    hta_cond_t  *conds;     /* pool-allocated only when nconds > 0 */
    ngx_uint_t   nconds;
} hta_rule_t;

typedef struct {
    ngx_uint_t   action;
    ngx_str_t    name;
    ngx_str_t    value;
    ngx_str_t    cond_env;      /* "env=VAR": apply only when VAR is set */
    unsigned     cond_negate:1; /* "env=!VAR": apply only when VAR is unset */
} hta_header_t;

typedef struct {
    ngx_int_t    code;
    ngx_str_t    response;
    unsigned     is_url:1;
} hta_errdoc_t;

typedef struct {
    ngx_str_t    value;
    unsigned     is_allow:1;
    unsigned     is_require:1;   /* came from "Require ip/host/env", not Allow/Deny */
} hta_access_t;

typedef struct {
    ngx_str_t    mime_type;
    ngx_str_t    extension;
} hta_addtype_t;

typedef struct {
    ngx_str_t    mime_type;
    ngx_int_t    seconds;
} hta_expires_t;

typedef struct {
    ngx_str_t    attribute;    /* e.g., "Request_URI", "User-Agent" */
    ngx_str_t    pattern;
    ngx_regex_t *regex;
    ngx_str_t    env_name;
    ngx_str_t    env_value;
    unsigned     unconditional:1;  /* SetEnv (no regex test) */
    unsigned     unset:1;          /* env_name should be unset, not set */
} hta_setenvif_t;

typedef struct {
    ngx_str_t    source;       /* URL path or regex pattern */
    ngx_str_t    target;       /* destination URL */
    ngx_regex_t *regex;        /* compiled regex (for RedirectMatch) */
    ngx_int_t    status;       /* 301, 302, 303, 410, etc. */
    unsigned     is_match:1;   /* RedirectMatch (regex) */
} hta_redirect_t;

typedef struct {
    ngx_str_t    pattern;
    ngx_regex_t *regex;
    unsigned     is_regex:1;
    /* access control */
    unsigned     has_acl:1;         /* mod_access_compat Allow/Deny/Order present */
    unsigned     require_denied:1;
    unsigned     require_granted:1;
    unsigned     has_require_host:1; /* Require ip/host/env present */
    unsigned     require_local:1;    /* Require local */
    unsigned     require_failed:1;   /* unsupported Require provider -> fail closed */
    ngx_uint_t   access_order;
    hta_access_t acl[HTA_MAX_FB_ACL];
    ngx_uint_t   nacl;
    /* auth */
    unsigned     auth_basic:1;
    unsigned     auth_valid_user:1;
    unsigned     auth_type_unsupported:1; /* AuthType set to a non-Basic scheme */
    ngx_str_t    auth_name;
    ngx_str_t    auth_user_file;
    ngx_str_t    auth_group_file;
    ngx_str_t    auth_users[8];
    ngx_uint_t   nauth_users;
    ngx_str_t    require_groups[8];
    ngx_uint_t   nrequire_groups;
    /* headers */
    hta_header_t headers[HTA_MAX_FB_HEADERS];
    ngx_uint_t   nheaders;
    /* types */
    ngx_str_t    force_type;
    hta_addtype_t addtypes[8];
    ngx_uint_t    naddtypes;
    /* SetHandler none / RemoveHandler: block script execution for this block */
    unsigned      exec_disabled:1;
} hta_files_block_t;

typedef struct {
    ngx_str_t    name;
    ngx_str_t    value;
    unsigned     is_admin:1;   /* php_admin_value / php_admin_flag */
} hta_php_value_t;

typedef struct {
    /* method bitmap of NGX_HTTP_GET|NGX_HTTP_POST|... that the block matches */
    ngx_uint_t   methods;
    /* if set, methods is an exclusion list (LimitExcept) */
    unsigned     is_except:1;
    /* access control inside the block */
    unsigned     has_acl:1;
    unsigned     require_denied:1;
    unsigned     require_granted:1;
    unsigned     has_require_host:1;
    unsigned     require_local:1;
    unsigned     require_failed:1;
    ngx_uint_t   access_order;
    hta_access_t acl[HTA_MAX_LB_ACL];
    ngx_uint_t   nacl;
    /* auth inside the block */
    unsigned     auth_basic:1;
    unsigned     auth_valid_user:1;
    unsigned     auth_type_unsupported:1;
    ngx_str_t    auth_name;
    ngx_str_t    auth_user_file;
    ngx_str_t    auth_group_file;
    ngx_str_t    auth_users[8];
    ngx_uint_t   nauth_users;
    ngx_str_t    require_groups[8];
    ngx_uint_t   nrequire_groups;
} hta_limit_block_t;

typedef struct {
    /* rewrite */
    unsigned          rewrite_on:1;
    ngx_str_t         rewrite_base;
    hta_rule_t        rules[HTA_MAX_RULES];
    ngx_uint_t        nrules;
    hta_cond_t        pending_conds[HTA_MAX_CONDS];
    ngx_uint_t        npending;

    /* directory index */
    ngx_str_t         index_files[HTA_MAX_INDEX];
    ngx_uint_t        nindex;

    /* error documents */
    hta_errdoc_t      errdocs[HTA_MAX_ERRDOCS];
    ngx_uint_t        nerrdocs;

    /* options */
    ngx_uint_t        opts_set;
    ngx_uint_t        opts_unset;
    unsigned          has_opts:1;

    /* access control */
    ngx_uint_t        access_order;
    hta_access_t      acl[HTA_MAX_USERS];
    ngx_uint_t        nacl;
    unsigned          has_acl:1;          /* mod_access_compat Allow/Deny/Order */
    unsigned          require_granted:1;
    unsigned          require_denied:1;
    unsigned          has_require_host:1; /* Require ip/host/env present */
    unsigned          require_local:1;    /* Require local */
    unsigned          require_failed:1;   /* unsupported Require provider -> deny */
    unsigned          has_unknown:1;      /* saw an unrecognized directive */
    unsigned          in_require_none:1;  /* transient: parsing inside <RequireNone> */

    /* response headers */
    hta_header_t      headers[HTA_MAX_HEADERS];
    ngx_uint_t        nheaders;

    /* request headers (RequestHeader directive: modify r->headers_in) */
    hta_header_t      req_headers[HTA_MAX_REQ_HEADERS];
    ngx_uint_t        nreq_headers;

    /* auth */
    unsigned          auth_basic:1;
    unsigned          auth_valid_user:1;
    unsigned          auth_type_unsupported:1; /* AuthType set to a non-Basic scheme */
    ngx_str_t         auth_name;
    ngx_str_t         auth_user_file;
    ngx_str_t         auth_users[HTA_MAX_USERS];
    ngx_uint_t        nauth_users;

    /* AuthGroupFile + Require group */
    ngx_str_t         auth_group_file;
    ngx_str_t         require_groups[HTA_MAX_GROUPS];
    ngx_uint_t        nrequire_groups;

    /* Satisfy Any/All - default All (auth AND access both required) */
    ngx_uint_t        satisfy;

    /* types */
    ngx_str_t         force_type;
    ngx_str_t         default_type;

    /* AddType */
    hta_addtype_t     addtypes[HTA_MAX_ADDTYPES];
    ngx_uint_t        naddtypes;

    /* Expires */
    unsigned          expires_active:1;
    unsigned          expires_active_set:1; /* ExpiresActive directive seen */
    hta_expires_t     expires[HTA_MAX_EXPIRES];
    ngx_uint_t        nexpires;
    ngx_int_t         expires_default;

    /* SetEnvIf */
    hta_setenvif_t    setenvifs[HTA_MAX_SETENVIF];
    ngx_uint_t        nsetenvifs;

    /* Redirect / RedirectMatch */
    hta_redirect_t    redirects[HTA_MAX_REDIRECTS];
    ngx_uint_t        nredirects;

    /* <Files> / <FilesMatch> blocks */
    hta_files_block_t files_blocks[HTA_MAX_FILES_BLOCKS];
    ngx_uint_t        nfiles_blocks;

    /* <Limit> / <LimitExcept> blocks */
    hta_limit_block_t limit_blocks[HTA_MAX_LIMIT_BLOCKS];
    ngx_uint_t        nlimit_blocks;

    /* php_value / php_admin_value / php_flag / php_admin_flag */
    hta_php_value_t   php_values[HTA_MAX_PHP_VALUES];
    ngx_uint_t        nphp_values;

    /* AddDefaultCharset */
    ngx_str_t         default_charset;

    /* FallbackResource - front-controller target when the file is absent */
    ngx_str_t         fallback_resource;

    /* SSLRequireSSL - require HTTPS */
    unsigned          ssl_required:1;

    /* SetHandler none / RemoveHandler .php / php_flag engine off:
     * block script (PHP) execution in this scope */
    unsigned          exec_disabled:1;

    /* directory of this .htaccess relative to the document root, with
     * trailing '/', e.g. "blog/" for /blog/.htaccess.  Used to match
     * RewriteRule patterns in Apache per-directory context. */
    ngx_str_t         dir_rel;

    /* meta */
    time_t            mtime;
    hta_fver_t        fver;         /* change fingerprint at parse time */
    size_t            mem_size;     /* approximate total pool footprint */
    size_t            regex_bytes;  /* compiled PCRE budget */
    ngx_uint_t        nregex;       /* compiled patterns in this file */
    ngx_pool_t       *pool;
    /* owner of the directory containing this .htaccess.  AuthUserFile /
     * AuthGroupFile must belong to the same tenant, otherwise one customer
     * can authenticate against another customer's password file. */
    uid_t             owner_uid;
    unsigned          owner_uid_valid:1;

    /* fail-closed state: a file that exists but cannot be parsed must never
     * silently turn into "no rules" */
    unsigned          invalid:1;
    /* <RequireAll> / <RequireAny> scope flags */
    unsigned          require_all:1;
    unsigned          require_any:1;
} hta_parsed_t;

typedef struct {
    /*
     * Store paths inline.  The old path_pool was never reclaimed on cache
     * eviction and grew without bound on every distinct path served.
     */
    u_char            path[HTA_MAX_PATH];
    ngx_uint_t        pathlen;
    uint32_t          path_hash;    /* FNV-1a for fast comparison */
    hta_parsed_t     *parsed;
    time_t            mtime;
    hta_fver_t        fver;
    int               wd;
} hta_cache_t;

typedef struct {
    ngx_flag_t        enable;
    ngx_str_t         filename;
    ngx_flag_t        strict;       /* fail closed (500) on unknown directives */
    ngx_flag_t        trust_proxy;  /* honor X-Forwarded-Proto for SSLRequireSSL */
    ngx_flag_t        owner_check;  /* require .ht* owner == parent dir owner */
    ngx_flag_t        allow_php_admin; /* accept php_admin_* from .htaccess */
    ngx_flag_t        allow_proxy_headers; /* let .htaccess set X-Forwarded-* */
    ngx_flag_t        allow_dangerous_php; /* allow auto_prepend_file etc. */
    ngx_flag_t        allow_security_unset; /* allow unsetting security hdrs */
    ngx_flag_t        symlink_check; /* block request paths escaping root */
    ngx_array_t      *env_allow;     /* variables SetEnv* may write */
} ngx_http_hta_loc_conf_t;

typedef struct {
    u_char      path[HTA_MAX_PATH];
    ngx_uint_t  pathlen;
    u_char     *content;       /* NUL-terminated, owned by pool */
    size_t      content_len;
    time_t      mtime;
    uid_t       owner_uid;
    unsigned    owner_valid:1;
    ngx_pool_t *pool;
} hta_passwd_entry_t;

typedef struct {
    hta_cache_t        cache[HTA_CACHE_SLOTS];
    ngx_uint_t         ncache;
    size_t             cache_bytes;
    int                inotify_fd;
    hta_passwd_entry_t passwd[HTA_PASSWD_SLOTS];
    ngx_uint_t         npasswd;
    size_t             passwd_bytes;
} ngx_http_hta_main_conf_t;

typedef struct {
    ngx_str_t  files[HTA_MAX_DEPTH];
    ngx_uint_t count;
    unsigned   error:1;   /* path truncated / depth cap hit: fail closed */
} hta_file_list_t;

typedef struct {
    ngx_str_t       uri;        /* URI at collection time */
    hta_file_list_t files;
    unsigned        collected:1;
    ngx_str_t       root_real;  /* cached realpath(clcf->root) */
    u_char         *root_conf;  /* the clcf->root it was resolved for */
    unsigned        root_real_set:1;
    /* regex CPU budget, kept on the main request's context */
    uint64_t        regex_ns;
    size_t          expand_bytes;
    ngx_uint_t      regex_count;
    unsigned        regex_over:1;
    unsigned        hdr_failed:1;
    /* document root opened once per request for file tests (openat2) */
    int             root_fd;
    unsigned        root_fd_set:1;
    /* [E=] assignments, re-applied in the preaccess phase after the
     * location's own "set" script, as SetEnv is */
    ngx_array_t    *env_late;
} hta_req_ctx_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Module extern
 * ═══════════════════════════════════════════════════════════════════════ */

extern ngx_module_t ngx_http_htaccess_module;


/* ═══════════════════════════════════════════════════════════════════════════
 * Cross-file function declarations
 * ═══════════════════════════════════════════════════════════════════════ */

/* module.c */
void hta_collect_files(ngx_http_request_t *r, ngx_str_t *root,
    ngx_str_t *filename, hta_file_list_t *list);
hta_file_list_t *hta_get_files(ngx_http_request_t *r, ngx_str_t *root,
    ngx_str_t *filename);

/* parser.c */
hta_parsed_t *hta_parse_file(ngx_pool_t *pool, u_char *filepath,
    ngx_log_t *log, ngx_uint_t owner_check);
ngx_int_t hta_file_owner_ok(u_char *path, ngx_log_t *log);
ngx_int_t hta_fd_owner_ok(ngx_fd_t fd, u_char *path, ngx_log_t *log);
ngx_int_t hta_fd_uid_ok(ngx_fd_t fd, uid_t expected_uid, u_char *path,
    ngx_log_t *log);
ngx_int_t hta_request_path_inside_root(ngx_http_request_t *r);
ngx_int_t hta_path_has_symlink(ngx_http_request_t *r);
ngx_int_t hta_location_supported(ngx_http_core_loc_conf_t *clcf);
ngx_int_t hta_pstrdup(ngx_http_request_t *r, ngx_str_t *dst,
    const ngx_str_t *src);
ngx_int_t hta_path_inside_root(ngx_http_request_t *r, ngx_str_t *path);
ngx_int_t hta_root_real(ngx_http_request_t *r, ngx_str_t *out);
ngx_int_t hta_wildcard_match(u_char *pattern, size_t plen, u_char *name,
    size_t nlen);
ngx_uint_t hta_tokenize(u_char *line, ngx_uint_t len, u_char **args,
    ngx_uint_t maxargs);

/*
 * Match a customer-supplied regex with PCRE2 match/depth limits.  The
 * module's patterns are untrusted input in shared hosting; nginx's
 * ngx_regex_exec() uses the default, effectively unbounded, match context.
 */
#define HTA_REGEX_ERROR  (-3)
ngx_int_t hta_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures,
    ngx_uint_t size);

/*
 * The request whose budget hta_regex_exec charges.  Every entry point of the
 * module (phase handlers, header filter, variables) sets it for the duration
 * of its call and restores the previous value; outside of them only the
 * per-match limits apply.
 */
ngx_http_request_t *hta_regex_enter(ngx_http_request_t *r);
void hta_regex_leave(ngx_http_request_t *prev);
hta_req_ctx_t *hta_req_ctx(ngx_http_request_t *r);
uint64_t hta_work_start(void);
ngx_int_t hta_work_stop(uint64_t t0);
ngx_int_t hta_work_alloc(size_t n);

/* rewrite.c */
ngx_int_t hta_expand_vars(ngx_http_request_t *r, ngx_str_t *src,
    ngx_str_t *dst);
ngx_int_t hta_apply_rules(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_apply_dirindex(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_apply_redirects(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_apply_fallback(ngx_http_request_t *r, ngx_str_t *fallback);
ngx_int_t hta_apply_setenvif(ngx_http_request_t *r, hta_parsed_t *h);
void hta_apply_late_env(ngx_http_request_t *r);
ngx_int_t hta_check_errdoc(ngx_http_request_t *r, hta_errdoc_t *errdocs,
    ngx_uint_t nerrdocs, ngx_int_t status);
ngx_int_t hta_protected_security_header(ngx_str_t *name);
ngx_int_t hta_dangerous_php_value(ngx_str_t *name);

/* access.c */
ngx_int_t hta_check_access(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_auth(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_files_access(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_files_auth(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_ssl(ngx_http_request_t *r, hta_parsed_t *h,
    ngx_uint_t trust_proxy);
ngx_int_t hta_check_limit_access(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_limit_auth(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_exec(ngx_http_request_t *r, hta_parsed_t *h);

/* rewrite.c */
void hta_apply_request_headers(ngx_http_request_t *r, hta_parsed_t *h);

/* header.c */
ngx_int_t hta_header_filter(ngx_http_request_t *r);
void hta_header_filter_init(ngx_http_output_header_filter_pt next);

/* cache.c */
hta_parsed_t *hta_cache_get(ngx_http_hta_main_conf_t *mc, u_char *path,
    ngx_uint_t plen);
void hta_cache_put(ngx_http_hta_main_conf_t *mc, u_char *path,
    ngx_uint_t plen, hta_parsed_t *parsed);
void hta_inotify_poll(ngx_http_hta_main_conf_t *mc, ngx_log_t *log);
hta_parsed_t *hta_get_parsed(ngx_http_request_t *r,
    ngx_http_hta_main_conf_t *mc, ngx_str_t *filepath);


#endif /* _NGX_HTTP_HTACCESS_MODULE_H_ */
