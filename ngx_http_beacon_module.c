
/**
 * 该模块用于跟踪用户行为，生成唯一行的beacon_id
 *
 * @author chenke
 *
 * @mail: chenke@dumpcache.com
 *
 * @createTime 2015-12-03
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#define is_space(c) ((c) == ' ' || (c) == '\t' || (c) == '\n')

typedef struct {
    ngx_flag_t beacon_switch;
} ngx_http_beacon_loc_conf_t;

void gen_beacon_id(ngx_str_t *beacon_id, ngx_http_request_t *r);
size_t get_root_domain(u_char **p, ngx_str_t *domain);
//static限定这两个变量只在当前文件中有效
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static void* ngx_http_beacon_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_beacon_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);
static ngx_int_t ngx_http_beacon_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_beacon_header_filter(ngx_http_request_t *r);
static ngx_command_t ngx_http_beacon_commands[] = { { ngx_string("beacon"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
                | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_beacon_loc_conf_t,
                beacon_switch), NULL }, ngx_null_command };

static ngx_http_module_t ngx_http_beacon_module_ctx = { NULL,
        ngx_http_beacon_init, NULL, NULL, NULL, NULL,
        ngx_http_beacon_create_loc_conf, ngx_http_beacon_merge_loc_conf };

ngx_module_t ngx_http_beacon_module = { NGX_MODULE_V1,
        &ngx_http_beacon_module_ctx, ngx_http_beacon_commands, NGX_HTTP_MODULE,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NGX_MODULE_V1_PADDING };

static ngx_int_t ngx_http_beacon_init(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_beacon_header_filter;

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "ngx http beacon init success !");

    return NGX_OK;
}

static void* ngx_http_beacon_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_beacon_loc_conf_t *mlcf;
    mlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_beacon_loc_conf_t));
    if (mlcf == NULL) {
        return NULL;
    }

    mlcf->beacon_switch = NGX_CONF_UNSET;

    return mlcf;
}

static char* ngx_http_beacon_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child) {
    ngx_http_beacon_loc_conf_t* prev = parent;
    ngx_http_beacon_loc_conf_t* conf = child;

    ngx_conf_merge_value(conf->beacon_switch, prev->beacon_switch, 0);

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_beacon_header_filter(ngx_http_request_t *r) {
    ngx_http_beacon_loc_conf_t *mlcf;
    ngx_table_elt_t **cookies;
    u_char *p, *v, *last, *end;
    ngx_str_t *cookie;
    ngx_uint_t i;
    u_char *domain = NULL;
    ngx_str_t beacon_id;
    ngx_str_t encode_beacon_id;
    ngx_table_elt_t *set_cookie = NULL;
    enum {
        pre_key = 0, key, pre_equal, pre_value, value
    } state;
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_beacon_module);
    if (mlcf->beacon_switch == 0) //beacon_switch=1,代表beacon功能开启
            {
        return ngx_http_next_header_filter(r);
    }

    p = NULL;
    cookie = NULL;
    end = NULL;
    cookies = (ngx_table_elt_t **) r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        cookie = &cookies[i]->value;
        p = ngx_strnstr(cookie->data, (char *) "beacon_id", cookie->len);
        if (p == NULL) {
            continue;
        }

        if (*(p + sizeof("beacon_id") - 1) == ' '
                || *(p + sizeof("beacon_id") - 1) == '=') {
            break;
        }
    }

    if (i >= r->headers_in.cookies.nelts) {
        goto not_found;
    }

    v = p + sizeof("beacon_id") - 1 + 1;
    last = cookie->data + cookie->len;

    state = 0;
    while (p < last) {
        switch (state) {
        case pre_key:
            if (*p == ';') {
                goto not_found;

            } else if (!is_space(*p)) {
                state = key;
            }

            break;

        case key:
            if (is_space(*p)) {
                state = pre_equal;

            } else if (*p == '=') {
                state = pre_value;
            }

            break;

        case pre_equal:
            if (*p == '=') {
                state = pre_value;

            } else if (!is_space(*p)) {
                goto not_found;
            }

            break;

        case pre_value:
            if (!is_space(*p)) {
                state = value;
                v = p--;
            }

            break;

        case value:
            if (*p == ';') {
                end = p + 1;
                goto finish;
            }

            if (p + 1 == last) {
                end = last;
                p++;
                goto finish;
            }

            break;

        default:
            break;
        }

        p++;
    }

    finish:

    if ((end - 1 - v) > 0L) {
        goto success;
    }

    not_found: set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "ngx_list_push set_cookie failed !!!");
    }
    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    size_t domain_len = 0;
    if (!r->headers_in.host) {
        domain_len = 23;
        domain = ngx_pcalloc(r->pool, 23);
        ngx_sprintf(domain, "%s", "jackmafoundation.org.cn");
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "host is null !!!,uri is:%s", r->uri.data);
    } else {
        domain_len = get_root_domain(&domain, &r->headers_in.host->value);
    }
    beacon_id.data = ngx_pcalloc(r->pool, 64);
    encode_beacon_id.data = ngx_pcalloc(r->pool, 64);
    gen_beacon_id(&beacon_id, r);
    //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, (char *)beacon_id.data);
    ngx_encode_base64url(&encode_beacon_id, &beacon_id);
    set_cookie->value.len = sizeof("beacon_id=") - 1 + encode_beacon_id.len
            + sizeof(";expires=") - 1 + sizeof("Thu, 31 Dec 2115 23:59:59 GMT")
            - 1 + sizeof(";max-age=") - 1 + sizeof("3153600000") - 1
            + sizeof(";domain=") - 1 + domain_len + sizeof(";path=") - 1
            + sizeof("/") - 1;
    u_char *pp = ngx_pcalloc(r->pool, set_cookie->value.len);

    if (pp == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "ngx_pcalloc set_cookie space failed !!!");
    }

    set_cookie->value.data = pp;
    pp = ngx_cpymem(pp, "beacon_id=", sizeof("beacon_id=") - 1);
    pp = ngx_cpymem(pp,encode_beacon_id.data, encode_beacon_id.len);
    pp = ngx_cpymem(pp, ";expires=", sizeof(";expires=") - 1);
    pp =
            ngx_cpymem(pp, "Thu, 31 Dec 2115 23:59:59 GMT", sizeof("Thu, 31 Dec 2115 23:59:59 GMT") - 1);
    pp = ngx_cpymem(pp, ";max-age=", sizeof(";max-age=") - 1);
    pp = ngx_cpymem(pp, "3153600000", sizeof("3153600000") - 1);
    pp = ngx_cpymem(pp, ";domain=", sizeof(";domain=") - 1);
    pp = ngx_cpymem(pp, domain, domain_len);
    pp = ngx_cpymem(pp, ";path=", sizeof(";path=")-1);
    pp = ngx_cpymem(pp, "/",sizeof("/")-1);

    success: return ngx_http_next_header_filter(r);
}

void gen_beacon_id(ngx_str_t *beacon_id, ngx_http_request_t *r) {
    //ip+进程号+时间戳+随机数
    ngx_pid_t ngx_pid;
    ngx_str_t loc_addr;
    struct timeval tv;
    ngx_usec_int_t us;

    ngx_gettimeofday(&tv);
    us = tv.tv_sec * 1000000 + tv.tv_usec;

    loc_addr.data = ngx_pcalloc(r->pool, 64);
    ngx_connection_local_sockaddr(r->connection, NULL, 0);
    loc_addr.len = ngx_sock_ntop(r->connection->local_sockaddr,
            r->connection->local_socklen, loc_addr.data, NGX_INET_ADDRSTRLEN,
            0);

    uint64_t rnd = (uint64_t) ngx_random() % 100;

    ngx_pid = ngx_getpid();

    ngx_sprintf(beacon_id->data, "%s-%XL-%XL-%XL", loc_addr.data, ngx_pid, us,
            rnd);

    beacon_id->len = ngx_strlen(beacon_id->data);
}

size_t get_root_domain(u_char **p, ngx_str_t *domain) {
    *p = domain->data;
    int i = domain->len - 1;
    ngx_flag_t is_dot = 0;
    while (1) {
        if (domain->data[i] == '.') {
            if (is_dot) {
                i++;
                if (ngx_strcmp(*p+i, "org.cn") == 0) {
                    is_dot = 0;
                } else {
                    break;
                }
            } else {
                is_dot = 1;
            }
        }
        if (i == 0) {
            break;
        }
        i--;
    }
    *p = *p + i;
    return domain->len - i;
}


