#include "type.h"
#include "def.h"
#include "debug.h"
#include "uci_fn.h"
#include "json-c/json.h"
#include "buffer_queue.h"
#include "thread_pool.h"

#include <curl/curl.h>
#include <zlib.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <arpa/inet.h>

enum {
    DPI_POSITION_AUTH_UPLINK    = 0x00,
    DPI_POSITION_AUTH_DOWNLINK  = 0x01,
    DPI_POSITION_BLACK_UPLINK   = 0x02,
    DPI_POSITION_BLACK_DOWNLINK = 0x03,
    DPI_POSITION_WHITE_UPLINK   = 0x04,
    DPI_POSITION_WHITE_DOWNLINK = 0x05,
    
    DPI_POSITION_MAXNUM         = 0x06
};
#define DPI_POSITION_VALID(pos) ((pos)>=DPI_POSITION_AUTH_UPLINK && (pos)<DPI_POSITION_MAXNUM)
static inline int8 *dpi_position_to_str(const int32 position)
{
    switch (position)
    {
        case DPI_POSITION_AUTH_UPLINK:
            return "AUTH-UPLINK";
        case DPI_POSITION_AUTH_DOWNLINK:
            return "AUTH-DOWNLINK";
        case DPI_POSITION_BLACK_UPLINK:
            return "BLACK-UPLINK";
        case DPI_POSITION_BLACK_DOWNLINK:
            return "BLACK-DOWNLINK";
        case DPI_POSITION_WHITE_UPLINK:
            return "WHITE-UPLINK";
        case DPI_POSITION_WHITE_DOWNLINK:
            return "WHITE-DOWNLINK";
        default:
            return "UNDEFINED";
    }
}

enum {
    DPI_L4_PROTO_ALL    = 0x00000000,
    DPI_L4_PROTO_TCP    = 0x00000001,
    DPI_L4_PROTO_UDP    = 0x00000002,
    DPI_L4_PROTO_OTHER  = 0xffffffff
};
static inline int8 *dpi_l4_proto_to_str(const int32 proto)
{
    switch (proto)
    {
        case DPI_L4_PROTO_ALL:
            return "ALL";
        case DPI_L4_PROTO_TCP:
            return "TCP";
        case DPI_L4_PROTO_UDP:
            return "UDP";
        case DPI_L4_PROTO_OTHER:
            return "OTHER";
        default:
            return "UNDEFINED";
    }
}

typedef struct dpi_grab_data_st{
    int32 position;
    uint64 timestamp;
    uint8 intra_mac[HWADDR_SIZE];
    uint32 intra_ip;
    uint32 outer_ip;
    int32 l4_proto;
    union {
        /*DPI_L4_PROTO_TCP == l4_proto*/
        struct {
            uint16 outer_port;
            uint16 tcp_dlen;
            uint16 grab_dlen;
            uint16 reserved;
        }tcp;
        /*DPI_L4_PROTO_UDP == l4_proto*/
        struct {
            uint16 outer_port;
            uint16 udp_dlen;
            uint16 grab_dlen;
            uint16 reserved;
        }udp;
        /*others L4 proto == l4_proto*/
        struct {
            uint16 ip_dlen;
            uint16 grab_dlen;
        }ip;
    };
} dpi_grab_data_t;

enum {
    DPID_WORKER_GATHER      = 0,
    DPID_WORKER_FORMAT      = 1,
    DPID_WORKER_COMPRESS    = 2,
    DPID_WORKER_UPLOADING   = 3,

    DPID_WORKER_MAXNUM      = 4
};
typedef struct {
    int32 worker;
    pthread_t thdid;
    void *arg_in;
    void *arg_out;
    buffer_queue_t *queue_in;
    buffer_queue_t *queue_out;
    thread_pool_t *tpool;
}dpid_workder_t;
static dpid_workder_t s_dpid_workers[DPID_WORKER_MAXNUM];


static void *dpid_gather_thread_func(void *arg)
{
    int32 fd = -1;
    fd_set rset;
    int32 nfds = -1;
    struct timeval tv;
    int32 num;
    buffer_t *rbuf;
    uint32 rlen;
    dpid_workder_t *worker = (dpid_workder_t *)arg;
    int8 *path = (int8 *)worker->arg_in;
    DB_INF("worker->worker[%d],worker->thdid[%d],worker->arg_in[%s],worker->arg_out[%s],"
        "worker->queue_in[%p],worker->queue_out[%p],worker->tpool[%p].",
        worker->worker, worker->thdid, worker->arg_in, worker->arg_out,
        worker->queue_in, worker->queue_out, worker->tpool);
    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        DB_ERR("open() call fail for path[%s].", path);
        return NULL;
    }
    while (1)
    {
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        nfds = fd >= nfds ? fd + 1 : nfds;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        num = select(nfds, &rset, NULL, NULL, &tv);
        if (0 == num)
        {
            usleep(100);
            continue;
        }
        else if (num < 0)
        {
            DB_ERR("select() call fail. errno[%d], strerr[%s]", errno, strerror(errno));
            continue;
        }
        else
        {
            rbuf = buffer_queue_buffer_alloc(worker->queue_out);
            if (NULL == rbuf)
            {
                DB_ERR("buffer_queue_buffer_alloc() call fail.");
                continue;
            }
            while ((rbuf->len + rbuf->offset) < rbuf->size)
            {
                rlen = read(fd, rbuf->buf + rbuf->offset + rbuf->len, rbuf->size - rbuf->offset - rbuf->len);
                if (rlen <= 0)
                    break;
                rbuf->len += rlen;
            }
            buffer_queue_enqueue(worker->queue_out, rbuf);
        }
    }
    close(fd);
    return arg;
}

static int32 bin_to_hex(const int8 *bin,
                        const uint32 bsize,
                        int8 *hex)
{
    uint32 i;
    int32 c;
    if (NULL == bin || NULL == hex)
        return -1;
    for (i=0; i<bsize; ++i)
    {
        c = *(int32 *)(bin+i);
        c &= 0x000000ff;
        sprintf(hex+(i*2), "%02x", c);
    }
    return 0;
}

static struct json_object *grab_data_to_json(const dpi_grab_data_t *grab)
{
    int8 tmp[512];
    struct tm *tm;
    struct json_object *jobj;
    struct json_object *jobj2;
    struct json_object *jobj3;
    struct json_object *jobj4;
    uint32 ipaddr;
    
    jobj = json_object_new_object();
    if (NULL == jobj)
        goto err;
    /*position*/
    jobj2 = json_object_new_string(dpi_position_to_str(grab->position));
    if (NULL == jobj2)
        goto err;
    json_object_object_add(jobj, "position", jobj2);
    /*timstamp*/
    bzero(tmp, sizeof(tmp));
    tm = gmtime((const time_t *)&grab->timestamp);
    snprintf(tmp, sizeof(tmp), "%04d-%02d-%02d %02d:%02d:%02d", 
            tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, 
            tm->tm_hour, tm->tm_min, tm->tm_sec);
    jobj2 = json_object_new_string(tmp);
    if (NULL == jobj2)
        goto err;
    json_object_object_add(jobj, "timestamp", jobj2);
    /*intra_mac*/
    bzero(tmp, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), MACSTR, MAC2STR(grab->intra_mac));
    jobj2 = json_object_new_string(tmp);
    if (NULL == jobj2)
        goto err;
    json_object_object_add(jobj, "intraMac", jobj2);
    /*intra_ip*/
    bzero(tmp, sizeof(tmp));
    ipaddr = htonl(grab->intra_ip);
    snprintf(tmp, sizeof(tmp), IPSTR, IP2STR(ipaddr));
    jobj2 = json_object_new_string(tmp);
    if (NULL == jobj2)
        goto err;
    json_object_object_add(jobj, "intraIp", jobj2);
    /*outer_ip*/
    bzero(tmp, sizeof(tmp));
    ipaddr = htonl(grab->outer_ip);
    snprintf(tmp, sizeof(tmp), IPSTR, IP2STR(ipaddr));
    jobj2 = json_object_new_string(tmp);
    if (NULL == jobj2)
        goto err;
    json_object_object_add(jobj, "outerIp", jobj2);
    /*l4_proto*/
    jobj2 = json_object_new_string(dpi_l4_proto_to_str(grab->l4_proto));
    if (NULL == jobj2)
        goto err;
    json_object_object_add(jobj, "l4Proto", jobj2);
    /*proto_data*/
    jobj2 = json_object_new_object();
    if (NULL == jobj2)
        goto err;
    json_object_object_add(jobj, "protoData", jobj2);
    switch (grab->l4_proto)
    {
        case DPI_L4_PROTO_TCP:
        {
            /*tcp*/
            jobj3 = json_object_new_object();
            if (NULL == jobj3)
                goto err;
            json_object_object_add(jobj2, "tcp", jobj3);
            /*tcp.outer_port*/
            jobj4 = json_object_new_int(grab->tcp.outer_port);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "outerPort", jobj4);
            /*tcp.tcp_dlen*/
            jobj4 = json_object_new_int((int32)grab->tcp.tcp_dlen);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "tcpDlen", jobj4);
            /*tcp.grab_dlen*/
            jobj4 = json_object_new_int((int32)grab->tcp.grab_dlen);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "grabDlen", jobj4);
            /*tcp.grab_data*/
            bzero(tmp, sizeof(tmp));
            bin_to_hex((int8 *)(grab+1), grab->tcp.grab_dlen, tmp);
            jobj4 = json_object_new_string(tmp);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "grabData", jobj4);
            break;
        }
        case DPI_L4_PROTO_UDP:
        {
            /*udp*/
            jobj3 = json_object_new_object();
            if (NULL == jobj3)
                goto err;
            json_object_object_add(jobj2, "udp", jobj3);
            /*udp.outer_port*/
            jobj4 = json_object_new_int(grab->tcp.outer_port);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "outerPort", jobj4);
            /*udp.udp_dlen*/
            jobj4 = json_object_new_int((int32)grab->udp.udp_dlen);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "udpDlen", jobj4);
            /*udp.grab_dlen*/
            jobj4 = json_object_new_int((int32)grab->tcp.grab_dlen);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "grabDlen", jobj4);
            /*udp.grab_data*/
            bzero(tmp, sizeof(tmp));
            bin_to_hex((int8 *)(grab+1), grab->tcp.grab_dlen, tmp);
            jobj4 = json_object_new_string(tmp);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "grabData", jobj4);
            break;
        }
        case DPI_L4_PROTO_OTHER:
        {
            /*ip*/
            jobj3 = json_object_new_object();
            if (NULL == jobj3)
                goto err;
            json_object_object_add(jobj2, "ip", jobj3);
            /*ip.ip_dlen*/
            jobj4 = json_object_new_int((int32)grab->ip.ip_dlen);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "ipDlen", jobj4);
            /*ip.grab_dlen*/
            jobj4 = json_object_new_int((int32)grab->ip.grab_dlen);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "grabDlen", jobj4);
            /*ip.grab_data*/
            bzero(tmp, sizeof(tmp));
            bin_to_hex((int8 *)(grab+1), grab->tcp.grab_dlen, tmp);
            jobj4 = json_object_new_string(tmp);
            if (NULL == jobj4)
                goto err;
            json_object_object_add(jobj3, "grabData", jobj4);
            break;
        }
        default:
            goto err;
    }

    return jobj;
err:
    if (NULL != jobj)
        json_object_put(jobj);
    return NULL;
}

static uint32 grab_data_size(const dpi_grab_data_t *grab)
{
    if (NULL == grab)
        return 0;
    switch (grab->l4_proto)
    {
        case DPI_L4_PROTO_TCP:
            return sizeof(*grab) + grab->tcp.grab_dlen;
        case DPI_L4_PROTO_UDP:
            return sizeof(*grab) + grab->udp.grab_dlen;
        case DPI_L4_PROTO_OTHER:
            return sizeof(*grab) + grab->ip.grab_dlen;
        default:
            return 0xffffffff;
    }
}

static uint32 grab_data_fomat_to_json(buffer_t *ibuf,
                                      buffer_t *obuf)
{
    dpi_grab_data_t *grab;
    struct json_object *jarray;
    struct json_object *jobj;
    const int8 *jarray_str = NULL;
    const int8 *jobj_str = NULL;
    uint32 jarray_size = 0;
    uint32 jobj_size = 0;
    uint32 out_space_size = obuf->size - obuf->offset - obuf->len;
    uint32 grab_size;
    BOOL is_jarray_empty = TRUE;
    jarray = json_object_new_array();
    if (NULL == jarray)
        return 0;
    while (ibuf->len > 0)
    {
        grab = (dpi_grab_data_t *)(ibuf->buf + ibuf->offset);
        grab_size = grab_data_size(grab);
        if (grab_size > ibuf->len)
            break;
        jobj = grab_data_to_json(grab);
        if (NULL == jobj)
            break;
        jarray_str = json_object_to_json_string_ext(jarray, JSON_C_TO_STRING_PLAIN);
        jarray_size = strlen(jarray_str);
        jobj_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
        jobj_size = strlen(jobj_str);
        /*reserved 3 bytes for ",{}"*/
        if ((jarray_size + jobj_size + 3) > out_space_size)
        {
            json_object_put(jobj);
            break;
        }
        json_object_array_add(jarray, jobj);
        is_jarray_empty = FALSE;
        ibuf->offset += grab_size;
        ibuf->len -= grab_size;
    }
    if (FALSE == is_jarray_empty)
    {
        jarray_str = json_object_to_json_string_ext(jarray, JSON_C_TO_STRING_PLAIN);
        jarray_size = strlen(jarray_str);
        memcpy(obuf->buf+obuf->offset, jarray_str, jarray_size);
        obuf->len += jarray_size;
    }
    else
        jarray_size = 0;
    json_object_put(jarray);
    return jarray_size;
}

static void *dpid_format_thread_func(void *arg)
{
    buffer_t *ibuf;
    buffer_t *obuf;
    uint32 osize;
    dpid_workder_t *worker = (dpid_workder_t *)arg;
    DB_INF("worker->worker[%d],worker->thdid[%d],worker->arg_in[%s],worker->arg_out[%s],"
        "worker->queue_in[%p],worker->queue_out[%p],worker->tpool[%p].",
        worker->worker, worker->thdid, worker->arg_in, worker->arg_out,
        worker->queue_in, worker->queue_out, worker->tpool);
    while (1)
    {
        ibuf = buffer_queue_dequeue(worker->queue_in);
        if (NULL == ibuf)
            continue;
        while (ibuf->len > 0)
        {
            obuf = buffer_queue_buffer_alloc(worker->queue_out);
            if (NULL == obuf)
                break;/*drop this buffer's data*/
            osize = grab_data_fomat_to_json(ibuf, obuf);
            if (osize <= 0)
            {
                buffer_queue_buffer_free(worker->queue_out, obuf);
                break;
            }
            else
                buffer_queue_enqueue(worker->queue_out, obuf);
        }
        buffer_queue_buffer_free(worker->queue_in, ibuf);
    }
    return arg;
}

static int32 data_compress(const buffer_t *ibuf,
                           buffer_t *obuf)
{
    int32 ret;
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (Z_OK != ret)
        return -1;
    strm.next_in = (uint8 *)ibuf->buf + ibuf->offset;
    strm.avail_in = ibuf->len;
    strm.next_out = (uint8 *)obuf->buf + obuf->offset + obuf->len;
    strm.avail_out = obuf->size - obuf->offset - obuf->len;
    ret = deflate(&strm, Z_FINISH);
    ASSERT(Z_STREAM_ERROR != ret);
    obuf->len += (obuf->size - obuf->offset - obuf->len) - strm.avail_out;
    deflateEnd(&strm);
    return 0;
}

static int32 data_uncompress(const buffer_t *ibuf,
                             buffer_t *obuf)
{
    int32 ret;
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = inflateInit(&strm);
    if (Z_OK != ret)
        return -1;
    strm.next_in = (uint8 *)ibuf->buf + ibuf->offset;
    strm.avail_in = ibuf->len;
    strm.next_out = (uint8 *)obuf->buf + obuf->offset + obuf->len;
    strm.avail_out = obuf->size - obuf->offset - obuf->len;
    ret = inflate(&strm, Z_FINISH);
    ASSERT(Z_STREAM_ERROR != ret);
    obuf->len += (obuf->size - obuf->offset - obuf->len) - strm.avail_out;
    inflateEnd(&strm);
    return 0;
}

static void *dpid_compress_thread_func(void *arg)
{
    buffer_t *ibuf;
    buffer_t *obuf;
    dpid_workder_t *worker = (dpid_workder_t *)arg;
    DB_INF("worker->worker[%d],worker->thdid[%d],worker->arg_in[%s],worker->arg_out[%s],"
        "worker->queue_in[%p],worker->queue_out[%p],worker->tpool[%p].",
        worker->worker, worker->thdid, worker->arg_in, worker->arg_out,
        worker->queue_in, worker->queue_out, worker->tpool);
    while (1)
    {
        ibuf = buffer_queue_dequeue(worker->queue_in);
        if (NULL == ibuf)
            continue;
        obuf = buffer_queue_buffer_alloc(worker->queue_out);
        if (0 != data_compress(ibuf, obuf))
            buffer_queue_buffer_free(worker->queue_out, obuf);
        else
            buffer_queue_enqueue(worker->queue_out, obuf);
        buffer_queue_buffer_free(worker->queue_in, ibuf);
    }
    return arg;
}

static void data_post_uploading(const buffer_t *buf,
                                const int8 *url)
{
    CURL *curl;
    CURLcode res;
    CURLFORMcode formrc;
    struct curl_httppost *formpost=NULL;
    struct curl_httppost *lastptr=NULL;
    struct curl_slist *headerlist=NULL;
    static const int8 *tmp = "Expect:";

    if (NULL == buf || NULL == url)
    {
        DB_ERR("buf[%p] OR url[%p] is NULL.", buf, url);
        goto out;
    }
    curl = curl_easy_init();
    if (NULL == curl)
    {
        DB_ERR("curl_easy_init() call fail.");
        goto out;
    }
    formrc = curl_formadd(&formpost,
                          &lastptr,
                          CURLFORM_COPYNAME, "grabedData",
                          CURLFORM_COPYCONTENTS, "grabedData",
                          CURLFORM_BUFFER, "grabedDataUploading",
                          CURLFORM_BUFFERPTR, buf->buf+buf->offset,
                          CURLFORM_BUFFERLENGTH, buf->len,
                          CURLFORM_END);
    if (CURL_FORMADD_OK != formrc)
    {
        DB_ERR("curl_formadd() call fail. errno[%d].", (int32)formrc);
        goto out;
    }
    headerlist = curl_slist_append(headerlist, tmp);
    if (NULL == headerlist)
    {
        DB_ERR("curl_slist_append() call fail.");
        goto out;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    res = curl_easy_perform(curl);
    if (CURLE_OK != res)
        DB_ERR("curl_easy_perform() call fail. errno[%d],errstr[%s].", 
            res, curl_easy_strerror(res));
out:
    if (NULL != curl)
        curl_easy_cleanup(curl);
    if (NULL != formpost)
        curl_formfree(formpost);
    if (NULL != headerlist)
        curl_slist_free_all(headerlist);
}

static void *dpid_uploading_thread_func(void *arg)
{
    buffer_t *buf;
    dpid_workder_t *worker = (dpid_workder_t *)arg;
    const int8 *url = (const int8 *)worker->arg_out;
    DB_INF("worker->worker[%d],worker->thdid[%d],worker->arg_in[%s],worker->arg_out[%s],"
        "worker->queue_in[%p],worker->queue_out[%p],worker->tpool[%p].",
        worker->worker, worker->thdid, worker->arg_in, worker->arg_out,
        worker->queue_in, worker->queue_out, worker->tpool);
    while (1)
    {
        buf = buffer_queue_dequeue(worker->queue_in);
        if (NULL == buf)
            continue;
        data_post_uploading(buf, url);
        buffer_queue_buffer_free(worker->queue_in, buf);
    }
    return arg;
}

static void usage(void)
{
    PRINTF("dpid usage:\n");
    PRINTF("  -f: Run dpid foreground.\n");
    PRINTF("  -h: Display this help and exit.\n");
}

#define DPID_PIDFILE_PATH  "/tmp/dpid_pidfile"
static int32 s_dpid_pidfile_fd = -1;

static inline void dpid_workder_kill(dpid_workder_t *worker,
                                     int32 signum)
{
    if (pthread_equal(pthread_self(), worker->thdid))
    {
        if (NULL != worker->arg_in)
        {
            free(worker->arg_in);
            worker->arg_in = NULL;
        }
        if (NULL != worker->arg_out)
        {
            free(worker->arg_out);
            worker->arg_out = NULL;
        }
        if (NULL != worker->queue_in)
        {
            buffer_queue_destroy(worker->queue_in);
            worker->queue_in = NULL;
        }
        if (NULL != worker->queue_out)
        {
            buffer_queue_destroy(worker->queue_out);
            worker->queue_out = NULL;
        }
        if (NULL != worker->tpool)
        {
            thread_pool_destroy(worker->tpool);
            worker->tpool = NULL;
        }
        bzero(worker, sizeof(*worker));
        worker->thdid = (pthread_t)-1;
        return;
    }
    if ((pthread_t)-1 != worker->thdid)
        pthread_kill(worker->thdid, signum);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif

static void signal_handler(int32 signum)
{
    int32 i;
    if (s_dpid_pidfile_fd >= 0)
    {
        struct flock lock;
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_END;
        lock.l_start = 0;
        lock.l_len = 0;
        fcntl(s_dpid_pidfile_fd, F_SETLK, &lock);
        close(s_dpid_pidfile_fd);
        s_dpid_pidfile_fd = -1;
        unlink(DPID_PIDFILE_PATH);
    }
    for (i=0; i<ARRAY_SIZE(s_dpid_workers); ++i)
        dpid_workder_kill(&s_dpid_workers[i], signum);
    exit(0);
}

static int32 signal_init(void)
{
    if (SIG_ERR == signal(SIGABRT, signal_handler))
    {
        perror("signal() SIGABRT");
        return -1;
    }
    if (SIG_ERR == signal(SIGINT, signal_handler))
    {
        perror("signal() SIGINT");
        return -1;
    }
    if (SIG_ERR == signal(SIGTERM, signal_handler))
    {
        perror("signal() SIGTERM");
        return -1;
    }
    if (SIG_ERR == signal(SIGTSTP, signal_handler))
    {
        perror("signal() SIGTSTP");
        return -1;
    }
    return 0;
}

typedef struct dpid_cfg_st{
    struct {
        int8 source[128];
        uint32 buffsize;
    }gather;
    struct {
        uint32 buffsize;
    }format;
    struct {
        uint32 buffsize;
    }compress;
    struct {
        int8 dest[128];
        uint32 buffsize;
    }uploading;
}dpid_cfg_t;

static dpid_cfg_t *dpid_cfg_load(void)
{
    dpid_cfg_t *cfg;
	int8 **array = NULL;
	int32 num = 0;
    cfg = (dpid_cfg_t *)malloc(sizeof(*cfg));
    if (NULL == cfg)
        return NULL;
    bzero(cfg, sizeof(*cfg));
    if (!uuci_get("dpid.gather.source", &array, &num))
    {
        strncpy(cfg->gather.source, array[0], sizeof(cfg->gather.source)-1);
		uuci_get_free(array, num);
	}
    else
        ASSERT(0);
    if (!uuci_get("dpid.gather.buffsize", &array, &num))
    {
        cfg->gather.buffsize = atoi(array[0]);
		uuci_get_free(array, num);
	}
    else
        ASSERT(0);
    if (!uuci_get("dpid.format.buffsize", &array, &num))
    {
        cfg->format.buffsize = atoi(array[0]);
		uuci_get_free(array, num);
	}
    else
        ASSERT(0);
    if (!uuci_get("dpid.compress.buffsize", &array, &num))
    {
        cfg->compress.buffsize = atoi(array[0]);
		uuci_get_free(array, num);
	}
    else
        ASSERT(0);
    if (!uuci_get("dpid.uploading.dest", &array, &num))
    {
        strncpy(cfg->uploading.dest, array[0], sizeof(cfg->uploading.dest)-1);
		uuci_get_free(array, num);
	}
    else
        ASSERT(0);
    if (!uuci_get("dpid.uploading.buffsize", &array, &num))
    {
        cfg->uploading.buffsize = atoi(array[0]);
		uuci_get_free(array, num);
	}
    else
        ASSERT(0);
    PRINTF("gather: source[%s],buffsize[%u].\n", cfg->gather.source, cfg->gather.buffsize);
    PRINTF("format: buffsize[%u].\n", cfg->format.buffsize);
    PRINTF("compress: buffsize[%u].\n", cfg->compress.buffsize);
    PRINTF("uploading: dest[%s],buffsize[%u].\n", cfg->uploading.dest, cfg->uploading.buffsize);
    return cfg;
}

int32 main(int32 argc, int8 **argv)
{
    BOOL foreground = FALSE;
    int32 ch;
    int32 ret;
    dpid_cfg_t *cfg;
    buffer_queue_t *queue;
    dpid_workder_t *worker;
    struct flock lock;

    while ((ch = getopt(argc, argv, "fh")) != -1)
    {
        switch (ch)
        {
        case 'f':
            foreground = TRUE;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            PRINTF("Unknown option: %c.\n", (int8)optopt);
            usage();
            exit(1);
        }
    }
    if (TRUE != foreground)
    {
        switch (fork())
        {
        case -1:
            DB_ERR("fork() call fail. errno[%d],errstr[%s].", errno, strerror(errno));
            exit(1);
        case 0:
            if (chdir("/"))
            {
                DB_ERR("chdir() call fail. errno[%d],errstr[%s].", errno, strerror(errno));
                exit(1);
            }
            break;
        default:
            exit(0);
        }
    }
    s_dpid_pidfile_fd = open(DPID_PIDFILE_PATH, O_RDWR|O_CREAT);
    if (s_dpid_pidfile_fd < 0)
    {
        DB_ERR("chdir() "DPID_PIDFILE_PATH" fail. errno[%d],errstr[%s].", errno, strerror(errno));
        exit(1);
    }
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_END;
    lock.l_start = 0;
    lock.l_len = 0;
    if (-1 == fcntl(s_dpid_pidfile_fd, F_SETLK, &lock))
    {
        DB_ERR("Could not run the progress. %s already running?", argv[0]);
        close(s_dpid_pidfile_fd);
        s_dpid_pidfile_fd = -1;
        exit(1);
    }
    else
    {
        int8 buf[64];
        int32 len;
        bzero(buf, sizeof(buf));
        len = sprintf(buf, "%u\n", (uint32)getpid());
        write(s_dpid_pidfile_fd, buf, len);
    }
    ret = signal_init();
    if (0 != ret)
    {
        DB_ERR("signal_init() call fail. errno[%d],errstr[%s].", errno, strerror(errno));
        exit(1);
    }

    cfg = dpid_cfg_load();
    if (NULL == cfg)
    {
        DB_ERR("dpid_cfg_load() call fail.");
        exit(1);
    }

    bzero(s_dpid_workers, sizeof(s_dpid_workers));
    /*gather*/
    worker = &s_dpid_workers[DPID_WORKER_GATHER];
    worker->worker = DPID_WORKER_GATHER;
    worker->arg_in = strdup(cfg->gather.source);
    queue = buffer_queue_create(cfg->gather.buffsize);
    if (NULL == queue)
    {
        DB_ERR("buffer_queue_create() call fail for gather.");
        exit(1);
    }
    worker->queue_out = queue;
    ret = pthread_create(&worker->thdid, NULL, dpid_gather_thread_func, worker);
    if (0 != ret)
    {
        DB_ERR("pthread_create() call fail for data gather.");
        exit(1);
    }
    /*format*/
    worker = &s_dpid_workers[DPID_WORKER_FORMAT];
    worker->worker = DPID_WORKER_FORMAT;
    worker->queue_in = queue;
    queue = buffer_queue_create(cfg->format.buffsize);
    if (NULL == queue)
    {
        DB_ERR("buffer_queue_create() call fail for format.");
        exit(1);
    }
    worker->queue_out = queue;
    ret = pthread_create(&worker->thdid, NULL, dpid_format_thread_func, worker);
    if (0 != ret)
    {
        DB_ERR("pthread_create() call fail for data format.");
        exit(1);
    }
    /*compress*/
    worker = &s_dpid_workers[DPID_WORKER_COMPRESS];
    worker->worker = DPID_WORKER_COMPRESS;
    worker->queue_in = queue;
    queue = buffer_queue_create(cfg->compress.buffsize);
    if (NULL == queue)
    {
        DB_ERR("buffer_queue_create() call fail for compress.");
        exit(1);
    }
    worker->queue_out = queue;
    ret = pthread_create(&worker->thdid, NULL, dpid_compress_thread_func, worker);
    if (0 != ret)
    {
        DB_ERR("pthread_create() call fail for data compress.");
        exit(1);
    }
    /*uploading*/
    worker = &s_dpid_workers[DPID_WORKER_UPLOADING];
    worker->worker = DPID_WORKER_UPLOADING;
    worker->arg_out = strdup(cfg->uploading.dest);
    worker->queue_in = queue;
    worker->thdid = pthread_self();
    dpid_uploading_thread_func(worker);
    return 0;
}
