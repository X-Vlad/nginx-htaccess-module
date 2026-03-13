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
#define HTA_CACHE_SLOTS       1024
#define HTA_PASSWD_SLOTS      256
#define HTA_INOTIFY_BUF       4096
#define HTA_MAX_CAPTURES      30

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
} hta_header_t;

typedef struct {
    ngx_int_t    code;
    ngx_str_t    response;
    unsigned     is_url:1;
} hta_errdoc_t;

typedef struct {
    ngx_str_t    value;
    unsigned     is_allow:1;
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
    unsigned     has_acl:1;
    unsigned     require_denied:1;
    unsigned     require_granted:1;
    ngx_uint_t   access_order;
    hta_access_t acl[HTA_MAX_FB_ACL];
    ngx_uint_t   nacl;
    /* auth */
    unsigned     auth_basic:1;
    unsigned     auth_valid_user:1;
    ngx_str_t    auth_name;
    ngx_str_t    auth_user_file;
    ngx_str_t    auth_users[8];
    ngx_uint_t   nauth_users;
    /* headers */
    hta_header_t headers[HTA_MAX_FB_HEADERS];
    ngx_uint_t   nheaders;
    /* types */
    ngx_str_t    force_type;
    hta_addtype_t addtypes[8];
    ngx_uint_t    naddtypes;
} hta_files_block_t;

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
    unsigned          has_acl:1;
    unsigned          require_granted:1;
    unsigned          require_denied:1;

    /* response headers */
    hta_header_t      headers[HTA_MAX_HEADERS];
    ngx_uint_t        nheaders;

    /* auth */
    unsigned          auth_basic:1;
    unsigned          auth_valid_user:1;
    ngx_str_t         auth_name;
    ngx_str_t         auth_user_file;
    ngx_str_t         auth_users[HTA_MAX_USERS];
    ngx_uint_t        nauth_users;

    /* types */
    ngx_str_t         force_type;
    ngx_str_t         default_type;

    /* AddType */
    hta_addtype_t     addtypes[HTA_MAX_ADDTYPES];
    ngx_uint_t        naddtypes;

    /* Expires */
    unsigned          expires_active:1;
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

    /* AddDefaultCharset */
    ngx_str_t         default_charset;

    /* meta */
    time_t            mtime;
    ngx_pool_t       *pool;
} hta_parsed_t;

typedef struct {
    u_char           *path;         /* allocated from mc->path_pool */
    ngx_uint_t        pathlen;
    uint32_t          path_hash;    /* FNV-1a for fast comparison */
    hta_parsed_t     *parsed;
    time_t            mtime;
    int               wd;
} hta_cache_t;

typedef struct {
    ngx_flag_t        enable;
    ngx_str_t         filename;
} ngx_http_hta_loc_conf_t;

typedef struct {
    u_char      path[HTA_MAX_PATH];
    ngx_uint_t  pathlen;
    u_char     *content;       /* NUL-terminated, owned by pool */
    size_t      content_len;
    time_t      mtime;
    ngx_pool_t *pool;
} hta_passwd_entry_t;

typedef struct {
    hta_cache_t        cache[HTA_CACHE_SLOTS];
    ngx_uint_t         ncache;
    int                inotify_fd;
    ngx_uint_t         poll_counter; /* amortize inotify read() syscall */
    ngx_pool_t        *path_pool;   /* owns all path strings in cache[] */
    hta_passwd_entry_t passwd[HTA_PASSWD_SLOTS];
    ngx_uint_t         npasswd;
} ngx_http_hta_main_conf_t;

typedef struct {
    ngx_str_t  files[HTA_MAX_DEPTH];
    ngx_uint_t count;
} hta_file_list_t;

typedef struct {
    ngx_str_t       uri;        /* URI at collection time */
    hta_file_list_t files;
    unsigned        collected:1;
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
    ngx_log_t *log);
ngx_uint_t hta_tokenize(u_char *line, ngx_uint_t len, u_char **args,
    ngx_uint_t maxargs);

/* rewrite.c */
ngx_int_t hta_expand_vars(ngx_http_request_t *r, ngx_str_t *src,
    ngx_str_t *dst);
ngx_int_t hta_apply_rules(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_apply_dirindex(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_apply_redirects(ngx_http_request_t *r, hta_parsed_t *h);
void hta_apply_setenvif(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_errdoc(ngx_http_request_t *r, hta_parsed_t *h,
    ngx_int_t status);

/* access.c */
ngx_int_t hta_check_access(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_auth(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_files_access(ngx_http_request_t *r, hta_parsed_t *h);
ngx_int_t hta_check_files_auth(ngx_http_request_t *r, hta_parsed_t *h);

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
