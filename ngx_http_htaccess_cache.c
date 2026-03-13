/*
 * ngx_http_htaccess_cache.c - Parsed .htaccess file cache
 *
 * Per-worker cache with inotify invalidation.
 * Falls back to stat()-based mtime checking when inotify unavailable.
 *
 * Paths are stored in mc->path_pool (pointer per entry, not inline array).
 * FNV-1a hash avoids memcmp on every entry during lookup.
 */

#include "ngx_http_htaccess_module.h"
#include <sys/inotify.h>


/* ═══════════════════════════════════════════════════════════════════════════
 * FNV-1a 32-bit hash - fast path comparison guard
 * ═══════════════════════════════════════════════════════════════════════ */

static uint32_t
hta_hash_path(const u_char *path, ngx_uint_t len)
{
    uint32_t   h = 2166136261U;
    ngx_uint_t i;
    for (i = 0; i < len; i++)
        h = (h ^ path[i]) * 16777619U;
    return h;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Cache lookup by filepath
 * ═══════════════════════════════════════════════════════════════════════ */

hta_parsed_t *
hta_cache_get(ngx_http_hta_main_conf_t *mc, u_char *path, ngx_uint_t plen)
{
    uint32_t   h = hta_hash_path(path, plen);
    ngx_uint_t i;

    for (i = 0; i < mc->ncache; i++) {
        if (mc->cache[i].path_hash == h
            && mc->cache[i].pathlen == plen
            && mc->cache[i].path != NULL
            && ngx_memcmp(mc->cache[i].path, path, plen) == 0)
        {
            return mc->cache[i].parsed;
        }
    }
    return NULL;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Cache insert/update - FIFO eviction when full
 * ═══════════════════════════════════════════════════════════════════════ */

void
hta_cache_put(ngx_http_hta_main_conf_t *mc, u_char *path, ngx_uint_t plen,
    hta_parsed_t *parsed)
{
    hta_cache_t *e;
    ngx_uint_t   i;
    uint32_t     h;

    if (plen >= HTA_MAX_PATH || mc->path_pool == NULL) return;

    h = hta_hash_path(path, plen);

    /* update existing */
    for (i = 0; i < mc->ncache; i++) {
        if (mc->cache[i].path_hash == h
            && mc->cache[i].pathlen == plen
            && mc->cache[i].path != NULL
            && ngx_memcmp(mc->cache[i].path, path, plen) == 0)
        {
            /* destroy old pool if re-parsing */
            if (mc->cache[i].parsed && mc->cache[i].parsed->pool
                && mc->cache[i].parsed != parsed)
            {
                ngx_destroy_pool(mc->cache[i].parsed->pool);
            }
            mc->cache[i].parsed = parsed;
            mc->cache[i].mtime  = parsed ? parsed->mtime : 0;
            return;
        }
    }

    /* evict oldest if full */
    if (mc->ncache >= HTA_CACHE_SLOTS) {
        if (mc->inotify_fd != -1 && mc->cache[0].wd != -1)
            inotify_rm_watch(mc->inotify_fd, mc->cache[0].wd);
        if (mc->cache[0].parsed && mc->cache[0].parsed->pool)
            ngx_destroy_pool(mc->cache[0].parsed->pool);
        /* path string stays in path_pool - can't free individually, bounded leak */
        ngx_memmove(&mc->cache[0], &mc->cache[1],
                     sizeof(hta_cache_t) * (HTA_CACHE_SLOTS - 1));
        mc->ncache--;
    }

    e = &mc->cache[mc->ncache];
    e->path = ngx_palloc(mc->path_pool, plen + 1);
    if (e->path == NULL) return;
    ngx_memcpy(e->path, path, plen);
    e->path[plen] = '\0';
    e->pathlen    = plen;
    e->path_hash  = h;
    e->parsed     = parsed;
    e->mtime      = parsed ? parsed->mtime : 0;
    e->wd         = -1;

    if (mc->inotify_fd != -1 && parsed) {
        e->wd = inotify_add_watch(mc->inotify_fd, (char *)path,
                                   IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF);
    }
    mc->ncache++;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * inotify poll - drain events and invalidate affected cache entries
 * ═══════════════════════════════════════════════════════════════════════ */

void
hta_inotify_poll(ngx_http_hta_main_conf_t *mc, ngx_log_t *log)
{
    u_char buf[HTA_INOTIFY_BUF];
    ssize_t len;
    u_char *p;

    if (mc->inotify_fd == -1) return;

    for (;;) {
        len = read(mc->inotify_fd, buf, sizeof(buf));
        if (len <= 0) break;

        p = buf;
        while (p < buf + len) {
            struct inotify_event *ev = (struct inotify_event *)p;
            ngx_uint_t i;
            for (i = 0; i < mc->ncache; i++) {
                if (mc->cache[i].wd == ev->wd) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                        "htaccess: invalidated \"%s\"", mc->cache[i].path);
                    if (mc->cache[i].parsed && mc->cache[i].parsed->pool)
                        ngx_destroy_pool(mc->cache[i].parsed->pool);
                    mc->cache[i].parsed = NULL;
                    mc->cache[i].wd     = -1;
                    break;
                }
            }
            p += sizeof(struct inotify_event) + ev->len;
        }
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Get parsed htaccess - cache lookup + parse on miss
 * ═══════════════════════════════════════════════════════════════════════ */

hta_parsed_t *
hta_get_parsed(ngx_http_request_t *r, ngx_http_hta_main_conf_t *mc,
    ngx_str_t *filepath)
{
    hta_parsed_t *h;
    uint32_t      fh;

    /* stat-based invalidation when inotify unavailable -
     * must run BEFORE hta_cache_get so stale entries are cleared first */
    if (mc->inotify_fd == -1) {
        fh = hta_hash_path(filepath->data, filepath->len);
        ngx_uint_t ci;
        for (ci = 0; ci < mc->ncache; ci++) {
            if (mc->cache[ci].path_hash == fh
                && mc->cache[ci].pathlen == filepath->len
                && mc->cache[ci].path != NULL
                && ngx_memcmp(mc->cache[ci].path, filepath->data,
                               filepath->len) == 0
                && mc->cache[ci].parsed)
            {
                ngx_file_info_t si;
                if (ngx_file_info(filepath->data, &si) == 0 &&
                    ngx_file_mtime(&si) != mc->cache[ci].mtime)
                {
                    ngx_destroy_pool(mc->cache[ci].parsed->pool);
                    mc->cache[ci].parsed = NULL;
                }
                break;
            }
        }
    }

    h = hta_cache_get(mc, filepath->data, filepath->len);
    if (h != NULL) return h;

    /* parse */
    ngx_pool_t *pool = ngx_create_pool(4096, r->connection->log);
    if (pool == NULL) return NULL;

    h = hta_parse_file(pool, filepath->data, r->connection->log);
    hta_cache_put(mc, filepath->data, filepath->len, h);

    if (h) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "htaccess: parsed \"%V\"", filepath);
    } else {
        ngx_destroy_pool(pool);
    }

    return h;
}
