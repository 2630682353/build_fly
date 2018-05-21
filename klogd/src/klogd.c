#include "klog.h"
#include "memcache.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

typedef struct buffer_list_st{
    buffer_t *head;
    buffer_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
}buffer_list_t;
//static buffer_list_t s_logd_buf_list_app = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};
static buffer_list_t s_logd_buf_list_kernel = {NULL, NULL, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};
static memcache_t *sp_logd_buf_cache = NULL;
static pthread_mutex_t s_logd_buf_cache_lock = PTHREAD_MUTEX_INITIALIZER;

#define LOGD_BUFFER_SIZE    ((32*1024) - sizeof(buffer_t))

static inline buffer_t *buffer_alloc(void)
{
    buffer_t *buf = NULL;
    pthread_mutex_lock(&s_logd_buf_cache_lock);
    buf = (buffer_t *)memcache_alloc(sp_logd_buf_cache);
    pthread_mutex_unlock(&s_logd_buf_cache_lock);
    if (NULL == buf)
        return buf;
    buf->size = LOGD_BUFFER_SIZE;
    buf->buf = (int8 *)(buf + 1);
    buf->offset = buf->len = 0;
    buf->next = NULL;
    return buf;
}

static inline void buffer_free(buffer_t *buf)
{
    pthread_mutex_lock(&s_logd_buf_cache_lock);
    memcache_free(sp_logd_buf_cache, buf);
    pthread_mutex_unlock(&s_logd_buf_cache_lock);
}

static inline int32 buffer_init(void)
{
    sp_logd_buf_cache = memcache_create(LOGD_BUFFER_SIZE+sizeof(buffer_t), 4);
    return NULL != sp_logd_buf_cache ? 0 : -1;
}

static inline void buffer_destroy(void)
{
    if (NULL == sp_logd_buf_cache)
        return;
    pthread_mutex_lock(&s_logd_buf_cache_lock);
    memcache_destroy(sp_logd_buf_cache);
    sp_logd_buf_cache = NULL;
    pthread_mutex_unlock(&s_logd_buf_cache_lock);
}

#define LOGD_FILE_PATH_DEFAULT  "/log/"
#define LOGD_FILE_PREFIX_APP    "app-log-"
#define LOGD_FILE_PREFIX_KER    "kernel-log-"
#define LOGD_FILE_MAXSIZE       (64*1024) /*64KB*/
#define LOGD_FILE_MAXNUM        (16)
static int8 *sp_logd_path = LOGD_FILE_PATH_DEFAULT;

static inline int32 logd_file_open(const BOOL kernel)
{
    int32 fd = -1;
    int32 i = 0;
    int8 filename[256];
    struct stat st;
    struct flock lock;
    if (0 != access(sp_logd_path, F_OK))
        mkdir(sp_logd_path, 0666);
    for (i=0; i<LOGD_FILE_MAXNUM; ++i)
    {
        bzero(filename, sizeof(filename));
        if (kernel)
            snprintf(filename, sizeof(filename), "%s" LOGD_FILE_PREFIX_KER "%02d.log", sp_logd_path, i+1);
        else
            snprintf(filename, sizeof(filename), "%s" LOGD_FILE_PREFIX_APP "%02d.log", sp_logd_path, i+1);
        if (0 == access(filename, W_OK))
        {
            stat(filename, &st);
            if (st.st_size < LOGD_FILE_MAXSIZE)
            {
                fd = open(filename, O_WRONLY | O_APPEND);
                break;
            }
        }
        else
        {
            fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IWUSR | S_IWGRP | S_IROTH | S_IWOTH);
            break;
        }
    }
    if (fd < 0)
    {
        time_t time_min = 0;
        int32 j = -1;
        for (i=0; i<LOGD_FILE_MAXNUM; ++i)
        {
            bzero(filename, sizeof(filename));
            if (kernel)
                snprintf(filename, sizeof(filename), "%s" LOGD_FILE_PREFIX_KER "%02d.log", sp_logd_path, i+1);
            else
                snprintf(filename, sizeof(filename), "%s" LOGD_FILE_PREFIX_APP "%02d.log", sp_logd_path, i+1);
            stat(filename, &st);
            if (0 == time_min || st.st_mtime < time_min)
            {
                time_min = st.st_mtime;
                j = i;
            }
        }
        bzero(filename, sizeof(filename));
        if (kernel)
            snprintf(filename, sizeof(filename), "%s" LOGD_FILE_PREFIX_KER "%02d.log", sp_logd_path, j+1);
        else
            snprintf(filename, sizeof(filename), "%s" LOGD_FILE_PREFIX_APP "%02d.log", sp_logd_path, j+1);
        fd = open(filename, O_WRONLY | O_TRUNC);
    }
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_END;
    lock.l_start = 0;
    lock.l_len = 0;
    if (-1 == fcntl(fd, F_SETLK, &lock))
    {
        perror("Lock file fail for write.\n");
        close(fd);
        fd = -1;
    }
    return fd;
}

static inline void logd_file_close(int32 fd)
{
    if (fd >= 0)
    {
        struct flock lock;
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_END;
        lock.l_start = 0;
        lock.l_len = 0;
        fcntl(fd, F_SETLK, &lock);
        close(fd);
    }
}

static void logd_file_save(const buffer_t *buf,
                           const BOOL kernel)
{
    int32 fd = -1;
    ssize_t size = 0;
    fd = logd_file_open(kernel);
    if (fd < 0)
        return;
    while (buf->len > size)
    {
        size += write(fd, buf->buf+buf->offset+size, buf->len-size);
        fsync(fd);
    }
    logd_file_close(fd);
}

static pthread_t s_klogd_recv_thdid;
static pthread_t s_klogd_save_thdid;

static void *klogd_save_thread_func(void *arg)
{
    buffer_t *buf;
    while (1)
    {
        pthread_mutex_lock(&s_logd_buf_list_kernel.mutex);
        if (NULL == s_logd_buf_list_kernel.head)
            pthread_cond_wait(&s_logd_buf_list_kernel.cond, &s_logd_buf_list_kernel.mutex);
        buf = s_logd_buf_list_kernel.head;
        s_logd_buf_list_kernel.head = s_logd_buf_list_kernel.head->next;
        if (NULL == s_logd_buf_list_kernel.head)
            s_logd_buf_list_kernel.tail = NULL;
        pthread_mutex_unlock(&s_logd_buf_list_kernel.mutex);
        logd_file_save(buf, TRUE);
        buffer_free(buf);
    }
    return arg;
}

static void klogd_run(void)
{
    int32 fd = -1;
    fd_set rset;
    int32 nfds = -1;
    struct timeval tv;
    int32 num;
    buffer_t *rbuf;
    uint32 rlen;
    fd = open("/dev/klog", O_RDONLY);
    if (fd < 0)
    {
        perror("open()");
        return ;
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
            printf("select() call fail. errno[%d], strerr[%s]\n", errno, strerror(errno));
            continue;
        }
        else
        {
            rbuf = buffer_alloc();
            if (NULL == rbuf)
            {
                printf("buffer_alloc() call fail.\n");
                continue;
            }
            while ((rbuf->len + rbuf->offset) < rbuf->size)
            {
                rlen = read(fd, rbuf->buf + rbuf->offset + rbuf->len, rbuf->size - rbuf->offset - rbuf->len);
                if (rlen <= 0)
                    break;
                rbuf->len += rlen;
            }
            pthread_mutex_lock(&s_logd_buf_list_kernel.mutex);
            if (NULL == s_logd_buf_list_kernel.tail)
            {
                s_logd_buf_list_kernel.tail = s_logd_buf_list_kernel.head = rbuf;
                pthread_cond_signal(&s_logd_buf_list_kernel.cond);
            }
            else
            {
                s_logd_buf_list_kernel.tail->next = rbuf;
                s_logd_buf_list_kernel.tail = rbuf;
            }
            pthread_mutex_unlock(&s_logd_buf_list_kernel.mutex);
        }
    }
    close(fd);
}


static void usage(void)
{
    printf("Logd usage:\n");
    printf("  -f: Run logd foreground.\n");
    printf("  -p path: The log storage to the specified directory.\n");
    printf("  -h: Display this help and exit.\n");
}

#define KLOGD_PIDFILE_PATH  "/tmp/klogd_pidfile"
static int32 s_pidfile_fd = -1;
static void signal_handler(int32 signum)
{
    if (pthread_self() == s_klogd_save_thdid)
        pthread_kill(s_klogd_recv_thdid, signum);
    else if (pthread_self() == s_klogd_recv_thdid)
    {
        pthread_kill(s_klogd_save_thdid, signum);
        buffer_destroy();
    }
    if (s_pidfile_fd >= 0)
    {
        struct flock lock;
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_END;
        lock.l_start = 0;
        lock.l_len = 0;
        fcntl(s_pidfile_fd, F_SETLK, &lock);
        close(s_pidfile_fd);
        unlink(KLOGD_PIDFILE_PATH);
    }
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

int32 main(int32 argc, int8 **argv)
{
    BOOL foreground = FALSE;
    int32 ch;
    int32 ret;
    struct flock lock;

    while ((ch = getopt(argc, argv, "fhp:")) != -1)
    {
        switch (ch)
        {
        case 'f':
            foreground = TRUE;
            break;
        case 'p':
            sp_logd_path = optarg;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            printf("Unknown option: %c\n", (int8)optopt);
            usage();
            exit(1);
        }
    }
    if (TRUE != foreground)
    {
        switch (fork())
        {
        case -1:
            perror("fork()");
            exit(1);
        case 0:
            if (chdir("/"))
            {
                perror("chdir()");
                exit(1);
            }
            break;
        default:
            exit(0);
        }
    }
    s_pidfile_fd = open(KLOGD_PIDFILE_PATH, O_RDWR|O_CREAT);
    if (s_pidfile_fd < 0)
    {
        perror("open() "KLOGD_PIDFILE_PATH" fial.\n");
        exit(1);
    }
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_END;
    lock.l_start = 0;
    lock.l_len = 0;
    if (-1 == fcntl(s_pidfile_fd, F_SETLK, &lock))
    {
        printf("Could not run the progress. %s already running?\n", argv[0]);
        close(s_pidfile_fd);
        s_pidfile_fd = -1;
        exit(1);
    }
    else
    {
        int8 buf[64];
        int32 len;
        bzero(buf, sizeof(buf));
        len = sprintf(buf, "%u\n", (uint32)getpid());
        write(s_pidfile_fd, buf, len);
    }
    ret = signal_init();
    if (0 != ret)
    {
        printf("signal_init() call fail.\n");
        exit(1);
    }
    ret = buffer_init();
    if (0 != ret)
    {
        printf("buffer_init() call fail.\n");
        exit(1);
    }
    ret = pthread_create(&s_klogd_save_thdid, NULL, klogd_save_thread_func, NULL);
    if (0 != ret)
    {
        perror("pthread_create() call fail for save");
        buffer_destroy();
        exit(1);
    }

    s_klogd_recv_thdid = pthread_self();
    klogd_run();
    return 0;
}
