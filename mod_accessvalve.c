#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"
#include "inet_ntop_cache.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* plugin config for all request/connections */
typedef struct {
    int bucket_size;
    int reset_duration;
    int ban_duration;
    int _cond_pos;  /* internal only */
} plugin_config;

struct s_ip_record {
    sock_addr addr;
    int tokens;
    time_t reset_when;
    time_t banned_until;
    plugin_config *conf;

    struct s_ip_record *next;
};
typedef struct s_ip_record ip_record;

typedef struct {
    PLUGIN_DATA;

    ip_record **ips;

    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_accessvalve_init) {
    plugin_data *p;

    p = calloc(1, sizeof(*p));
    return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_accessvalve_free) {
    plugin_data *p = p_d;
    size_t i;
    ip_record *cur, *prev;

    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];

            if (!s) continue;
            free(s);
        }
        free(p->config_storage);
    }

    if (p->ips) {
        for (i = 0; i < srv->config_context->used; i++) {
            cur = p->ips[i];
            while (cur) {
                prev = cur;
                cur = cur->next;
                free(prev);
            }
        }
        free(p->ips);
    }
    free(p);

    return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_accessvalve_set_defaults) {
    plugin_data *p = p_d;
    size_t i;

    config_values_t cv[] = {
        { "accessvalve.bucket-size",    NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
        { "accessvalve.reset-duration", NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
        { "accessvalve.ban-duration",   NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
        { NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (!p) return HANDLER_ERROR;

    p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
    p->ips = calloc(1, srv->config_context->used * sizeof(ip_record *));

    for (i = 0; i < srv->config_context->used; i++) {
        plugin_config *s;
        ip_record *r;

        s = calloc(1, sizeof(plugin_config));
        s->bucket_size    = 0;
        s->reset_duration = 60;
        s->ban_duration   = 900;
        s->_cond_pos      = i;

        cv[0].destination = &(s->bucket_size);
        cv[1].destination = &(s->reset_duration);
        cv[2].destination = &(s->ban_duration);

        p->config_storage[i] = s;

        r = calloc(1, sizeof(ip_record));
        r->next = NULL;

        p->ips[i] = r;

        if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_accessvalve_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];
    int merged = 0;

    PATCH(bucket_size);
    PATCH(reset_duration);
    PATCH(ban_duration);
    PATCH(_cond_pos);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("accessvalve.bucket-size"))) {
                PATCH(bucket_size);
                merged++;
            }
            else if (buffer_is_equal_string(du->key, CONST_STR_LEN("accessvalve.reset-duration"))) {
                PATCH(reset_duration);
                merged++;
            }
            else if (buffer_is_equal_string(du->key, CONST_STR_LEN("accessvalve.ban-duration"))) {
                PATCH(ban_duration);
                merged++;
            }
        }

        if (merged)
            PATCH(_cond_pos);
    }

    return 0;
}
#undef PATCH

static ip_record *get_or_create_ip_record(server *srv, connection *con, plugin_data *p) {
    UNUSED(srv);
    ip_record *cur = NULL, *prev = NULL;
    ip_record *head = p->ips[ p->conf._cond_pos ];
    ip_record *new_record;

    for (cur = head->next, prev = head; cur; prev = cur, cur = cur->next) {
        if (con->dst_addr.ipv4.sin_addr.s_addr == cur->addr.ipv4.sin_addr.s_addr) {
            return cur;
        }
    }

    new_record = calloc(1, sizeof(ip_record));
    assert(new_record);

    new_record->addr = con->dst_addr;
    new_record->tokens = p->conf.bucket_size;
    new_record->reset_when = time(NULL) + p->conf.reset_duration;
    new_record->banned_until = 0;
    new_record->conf = &(p->conf);
    new_record->next = NULL;
    prev->next = new_record;

    return new_record;
}

URIHANDLER_FUNC(mod_accessvalve_uri_handler) {
    plugin_data *p = p_d;
    ip_record *rec;
    UNUSED(srv);

    if (con->mode != DIRECT) return HANDLER_GO_ON;
    mod_accessvalve_patch_connection(srv, con, p);

    if (0 >= p->conf.bucket_size) return HANDLER_GO_ON;

    rec = get_or_create_ip_record(srv, con, p);

    if (!rec->banned_until && (--rec->tokens < 0)) {
        log_error_write(srv, __FILE__, __LINE__, "ss", "Banned:", inet_ntop_cache_get_ip(srv, &rec->addr));
        rec->banned_until = time(NULL) + p->conf.ban_duration;
        rec->reset_when   = rec->banned_until;
    }

    if (rec->banned_until) {
        if (rec->banned_until > time(NULL)) {
            /* banned */
            con->http_status = 503;
            return HANDLER_FINISHED;
        }
        else {
            /* unban */
            log_error_write(srv, __FILE__, __LINE__, "ss", "Unbanned:", inet_ntop_cache_get_ip(srv, &rec->addr));
            rec->banned_until = 0;
            rec->tokens = p->conf.bucket_size;
            rec->reset_when = time(NULL) + p->conf.reset_duration;
        }
    }

    return HANDLER_GO_ON;
}

TRIGGER_FUNC(mod_accessvalve_trigger) {
    plugin_data *p = p_d;
    size_t i;
    ip_record *head = NULL, *cur = NULL, *prev = NULL;

    for (i = 0; i < srv->config_context->used; ++i) {
        head = p->ips[i];
        for (cur = head->next, prev = head; cur;) {
            if (cur->tokens == cur->conf->bucket_size) {
                /* remove */
                prev->next = cur->next;
                prev = cur, cur = cur->next;
                free(prev);
                continue;
            }

            if (time(NULL) >= cur->reset_when) {
                if (cur->banned_until) {
                    log_error_write(srv, __FILE__, __LINE__, "ss", "Unbanned:", inet_ntop_cache_get_ip(srv, &cur->addr));
                }
                cur->banned_until = 0;
                cur->tokens = cur->conf->bucket_size;
                cur->reset_when = time(NULL) + cur->conf->reset_duration;
            }

            prev = cur, cur = cur->next;
        }
    }

    return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */
int mod_accessvalve_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = buffer_init_string("accessvalve");

    p->init         = mod_accessvalve_init;
    p->set_defaults = mod_accessvalve_set_defaults;
    p->cleanup      = mod_accessvalve_free;

    p->handle_uri_clean = mod_accessvalve_uri_handler;
    p->handle_trigger   = mod_accessvalve_trigger;

    p->data        = NULL;

    return 0;
}
