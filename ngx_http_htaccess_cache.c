/*
 * ngx_http_htaccess_cache.c - Parsed .htaccess file cache
 *
 * Per-worker cache with inotify invalidation.
 * Falls back to stat()-based mtime checking when inotify unavailable.
 *
 * Paths are stored inline in each cache entry (no unbounded path pool).
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

    if (plen >= HTA_MAX_PATH) return;

    h = hta_hash_path(path, plen);

    /* update existing */
    for (i = 0; i < mc->ncache; i++) {
        if (mc->cache[i].path_hash == h
            && mc->cache[i].pathlen == plen
            && ngx_memcmp(mc->cache[i].path, path, plen) == 0)
        {
            /* destroy old pool if re-parsing */
            if (mc->cache[i].parsed && mc->cache[i].parsed->pool
                && mc->cache[i].parsed != parsed)
            {
                mc->cache_bytes -= mc->cache[i].parsed->mem_size;
                ngx_destroy_pool(mc->cache[i].parsed->pool);
            }
            if (parsed != mc->cache[i].parsed && parsed) {
                mc->cache_bytes += parsed->mem_size;
            }
            mc->cache[i].parsed = parsed;
            mc->cache[i].mtime  = parsed ? parsed->mtime : 0;
            /* Re-arm the inotify watch. After the first invalidation the watch
             * descriptor was cleared (wd=-1); without re-adding it here only the
             * first edit per file would ever be detected and later edits would
             * serve stale config until restart. inotify_add_watch on the same
             * path returns the existing wd for a still-watched file, or a fresh
             * one after IN_DELETE_SELF/IN_MOVE_SELF. */
            if (mc->inotify_fd != -1 && parsed && mc->cache[i].wd == -1) {
                mc->cache[i].wd = inotify_add_watch(mc->inotify_fd,
                    (char *) path, IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF);
            }
            return;
        }
    }

    /*
     * Evict oldest entries until both the slot count and the byte budget
     * fit.  The old implementation only counted slots, so 1024 x 1 MB
     * .htaccess files could take gigabytes per worker.
     */
    while (mc->ncache > 0
           && (mc->ncache >= HTA_CACHE_SLOTS
               || (parsed && mc->cache_bytes + parsed->mem_size
                              > HTA_CACHE_MAX_BYTES)))
    {
        if (mc->inotify_fd != -1 && mc->cache[0].wd != -1)
            inotify_rm_watch(mc->inotify_fd, mc->cache[0].wd);
        if (mc->cache[0].parsed && mc->cache[0].parsed->pool) {
            mc->cache_bytes -= mc->cache[0].parsed->mem_size;
            ngx_destroy_pool(mc->cache[0].parsed->pool);
        }
        ngx_memmove(&mc->cache[0], &mc->cache[1],
                     sizeof(hta_cache_t) * (mc->ncache - 1));
        mc->ncache--;
    }

    e = &mc->cache[mc->ncache];
    if (plen >= sizeof(e->path)) return;
    ngx_memcpy(e->path, path, plen);
    e->path[plen] = '\0';
    e->pathlen    = plen;
    e->path_hash  = h;
    e->parsed     = parsed;
    e->mtime      = parsed ? parsed->mtime : 0;
    e->wd         = -1;

    if (parsed) {
        mc->cache_bytes += parsed->mem_size;
    }

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
    ngx_uint_t i;

    if (mc->inotify_fd == -1) return;

    for (;;) {
        len = read(mc->inotify_fd, buf, sizeof(buf));
        if (len <= 0) break;

        p = buf;
        while (p < buf + len) {
            struct inotify_event *ev = (struct inotify_event *)p;

            if (p + sizeof(struct inotify_event) > buf + len
                || p + sizeof(struct inotify_event) + ev->len > buf + len)
            {
                break;
            }

            /*
             * Drop the kernel watch as soon as the entry is invalidated.
             * Previously wd was set to -1 without inotify_rm_watch(); if
             * the entry was later evicted, the watch stayed in the kernel
             * forever and could exhaust max_user_watches.
             */
            if (mc->inotify_fd != -1 && ev->wd != -1
                && !(ev->mask & IN_IGNORED))
            {
                (void) inotify_rm_watch(mc->inotify_fd, ev->wd);
            }

            for (i = 0; i < mc->ncache; i++) {
                if (mc->cache[i].wd == ev->wd) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                        "htaccess: invalidated \"%s\"", mc->cache[i].path);
                    if (mc->cache[i].parsed && mc->cache[i].parsed->pool) {
                        mc->cache_bytes -= mc->cache[i].parsed->mem_size;
                        ngx_destroy_pool(mc->cache[i].parsed->pool);
                    }
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
 * Compute the directory of a .htaccess relative to the document root.
 * ═══════════════════════════════════════════════════════════════════════ */

static void
hta_set_dir_rel(ngx_http_request_t *r, hta_parsed_t *h, ngx_str_t *filepath)
{
    ngx_http_core_loc_conf_t *clcf;
    u_char                   *rel, *slash;
    size_t                    rlen, dlen;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf == NULL || clcf->root.len == 0
        || filepath->len <= clcf->root.len
        || ngx_memcmp(filepath->data, clcf->root.data, clcf->root.len) != 0)
    {
        return;
    }

    rel = filepath->data + clcf->root.len;
    rlen = filepath->len - clcf->root.len;

    while (rlen > 0 && *rel == '/') {
        rel++;
        rlen--;
    }

    slash = NULL;
    {
        u_char *p;
        for (p = rel; p < rel + rlen; p++) {
            if (*p == '/') slash = p;
        }
    }

    if (slash == NULL) {
        return;  /* root .htaccess */
    }

    dlen = slash - rel;
    h->dir_rel.data = ngx_pnalloc(h->pool, dlen + 1);
    if (h->dir_rel.data == NULL) {
        return;
    }
    ngx_memcpy(h->dir_rel.data, rel, dlen);
    h->dir_rel.data[dlen] = '/';
    h->dir_rel.len = dlen + 1;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Get parsed htaccess - cache lookup + parse on miss
 * ═══════════════════════════════════════════════════════════════════════ */

hta_parsed_t *
hta_get_parsed(ngx_http_request_t *r, ngx_http_hta_main_conf_t *mc,
    ngx_str_t *filepath)
{
    hta_parsed_t            *h;
    ngx_http_hta_loc_conf_t *lcf;
    uint32_t                 fh;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_htaccess_module);

    /*
     * mtime invalidation.  Run it for entries without an inotify watch too:
     * inotify_add_watch() can fail on NFS / watch-limit exhaustion, and the
     * old code then had neither a watch nor the stat fallback.
     */
    fh = hta_hash_path(filepath->data, filepath->len);
    {
        ngx_uint_t ci;
        for (ci = 0; ci < mc->ncache; ci++) {
            if (mc->cache[ci].path_hash == fh
                && mc->cache[ci].pathlen == filepath->len
                && ngx_memcmp(mc->cache[ci].path, filepath->data,
                               filepath->len) == 0
                && mc->cache[ci].parsed)
            {
                ngx_file_info_t si;

                if (mc->cache[ci].wd != -1 && mc->inotify_fd != -1) {
                    break;
                }

                if (ngx_file_info(filepath->data, &si) != 0
                    || ngx_file_mtime(&si) != mc->cache[ci].mtime)
                {
                    mc->cache_bytes -= mc->cache[ci].parsed->mem_size;
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

    if (!hta_path_inside_root(r, filepath)) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    h = hta_parse_file(pool, filepath->data, r->connection->log,
                       lcf ? lcf->owner_check : 1);
    if (h != NULL) {
        if (h->mem_size > HTA_CACHE_MAX_BYTES) {
            ngx_destroy_pool(pool);
            return NULL;
        }
        hta_set_dir_rel(r, h, filepath);
    }
    hta_cache_put(mc, filepath->data, filepath->len, h);

    if (h) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "htaccess: parsed \"%V\"", filepath);
    } else {
        ngx_destroy_pool(pool);
    }

    return h;
}
