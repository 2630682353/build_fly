#include "type.h"
#include "def.h"
#include "spinlock.h"
#include "log.h"
#include "time.h"
#include "debug.h"

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

static buffer_t *sp_klog_used_buf_head = NULL;
static buffer_t *sp_klog_used_buf_tail = NULL;
static buffer_t *sp_klog_free_buf_head = NULL;
static buffer_t *sp_klog_free_buf_tail = NULL;
static uint32 s_klog_buf_number = 0;
#define KLOG_BUF_MAX_NUMBER (32)
static spinlock_t s_klog_lock;
static int32 s_klog_level = L_DEBUG;
static BOOL s_klog_on = TRUE;
#define KLOG_BUF_SIZE   (PAGE_SIZE - sizeof(buffer_t))

static inline buffer_t *klog_buf_alloc(void)
{
    buffer_t *buf = NULL;
    if (s_klog_buf_number >= KLOG_BUF_MAX_NUMBER)
        return NULL;
    buf = (buffer_t *)malloc(KLOG_BUF_SIZE + sizeof(buffer_t));
    if (likely(NULL != buf))
    {
        buf->buf = (int8 *)(buf+1);
        buf->size = KLOG_BUF_SIZE;
        buf->offset = buf->len = 0;
        buf->next = NULL;
        ++s_klog_buf_number;
    }
    return buf;
}

static inline void klog_buf_free(buffer_t *buf)
{
    if (likely(NULL != buf))
    {
        free(buf);
        --s_klog_buf_number;
    }
}

static inline void klog_buf_reset(buffer_t *buf)
{
    if (likely(NULL != buf))
    {
        buf->offset = 0;
        buf->len = 0;
        buf->next = NULL;
    }
}

void klog_logging(const int32 level,
                  int8 *fmt, ...)
{
    int8 buf[512];
    int32 len = 0;
    int32 copyed = 0;
    int32 size;
    buffer_t *tmp;
    tm_t tm;
    va_list va;
    int8 *levelstr[] = {[L_CRIT]    = "CRIT",
                        [L_ERR]     = "ERR",
                        [L_WARNING] = "WARNING",
                        [L_NOTICE]  = "NOTICE",
                        [L_INFO]    = "INFO",
                        [L_DEBUG]   = "DEBUG"};
    if (FALSE == s_klog_on || !LOG_LEVEL_VALID(level) || level > s_klog_level)
        return;
    curtime_tm(&tm);
    len += snprintf(buf+len, sizeof(buf)-len, "%d-%02d-%02d %02d:%02d:%02d [%s]: ",
                tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, 
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                levelstr[level]);
    va_start(va, fmt);
    len += vsnprintf(buf+len, sizeof(buf)-len, fmt, va);
    va_end(va);
    len += snprintf(buf+len, sizeof(buf)-len, "\r\n");
    spinlock_lock(&s_klog_lock);
    while (copyed < len)
    {
        if ((NULL == sp_klog_used_buf_tail) 
            || ((sp_klog_used_buf_tail->offset + sp_klog_used_buf_tail->len) >= sp_klog_used_buf_tail->size))
        {
            if (NULL != sp_klog_free_buf_head)
            {
                tmp = sp_klog_free_buf_head;
                sp_klog_free_buf_head = sp_klog_free_buf_head->next;
                if (NULL == sp_klog_free_buf_head)
                    sp_klog_free_buf_tail = NULL;
            }
            else
            {
                tmp = klog_buf_alloc();
                if (NULL == tmp)
                {
                    if (NULL != sp_klog_used_buf_head)
                    {
                        tmp = sp_klog_used_buf_head;
                        sp_klog_used_buf_head = sp_klog_used_buf_head->next;
                        klog_buf_reset(tmp);
                    }
                    else
                    {
                        DB_WAR("There is no space to store log, discard this log.");
                        spinlock_unlock(&s_klog_lock);
                        return;
                    }
                }
            }
            tmp->next = NULL;
            if (NULL == sp_klog_used_buf_tail)
            {
                ASSERT(NULL == sp_klog_free_buf_head);
                sp_klog_used_buf_head = sp_klog_used_buf_tail = tmp;
            }
            else
            {
                sp_klog_used_buf_tail->next = tmp;
                sp_klog_used_buf_tail = tmp;
            }
        }
        else
            tmp = sp_klog_used_buf_tail;
        size = tmp->size - tmp->offset - tmp->len;
        size = size >= (len-copyed) ? (len-copyed) : size;
        memcpy(tmp->buf+tmp->offset+tmp->len, buf+copyed, size);
        tmp->len += size;
        copyed += size;
    }
    spinlock_unlock(&s_klog_lock);
}

EXPORT_SYMBOL(klog_logging);

static int32 klog_open(struct inode *inode, 
                       struct file *file)
{
    return 0;
}

static int32 klog_close(struct inode *inode, 
                        struct file *file)
{
    return 0;
}

static ssize_t klog_read(struct file *file,
	                     int8 __user *buf, 
	                     size_t size, 
	                     loff_t *ppos)
{
    ssize_t copyed = 0;
    ssize_t len = 0;
    buffer_t *tmp;
    spinlock_lock(&s_klog_lock);
    while (NULL != sp_klog_used_buf_head && copyed < size)
    {
        tmp = sp_klog_used_buf_head;
        len = ((size - copyed) >= tmp->len) ? tmp->len : (size - copyed);
        copy_to_user(buf+copyed, tmp->buf+tmp->offset, len);
        tmp->len -= len;
        copyed += len;
        if (tmp->len > 0)
        {
            tmp->offset += len;
            break;
        }
        else
        {
            sp_klog_used_buf_head = sp_klog_used_buf_head->next;
            if (NULL == sp_klog_used_buf_head)
                sp_klog_used_buf_tail = NULL;
            if (NULL != sp_klog_free_buf_tail)
            {
                sp_klog_free_buf_tail->next = tmp;
                sp_klog_free_buf_tail = tmp;
            }
            else
            {
                sp_klog_free_buf_head = sp_klog_free_buf_tail = tmp;
            }
            klog_buf_reset(tmp);
        }
    }
    spinlock_unlock(&s_klog_lock);
    return copyed;
}

static ssize_t klog_write(struct file *file,
	                      const int8 __user *buf, 
	                      size_t size, 
	                      loff_t *ppos)
{
    return -EPERM;
}

static uint32 klog_poll(struct file *file, 
                        poll_table *poll)
{
    uint32 mask = 0;
    spinlock_lock(&s_klog_lock);
    if (NULL != sp_klog_used_buf_head)
        mask |= POLLIN | POLLRDNORM;
    spinlock_unlock(&s_klog_lock);
    return mask;
}

static long klog_ioctl(struct file *file, 
                       uint32 cmd,
                       unsigned long arg)
{
    switch (cmd)
    {
    case LOGCMD_CHANGE_LEVEL:
        if (0 == arg)
        {
            DB_ERR("parameter arg is NULL.");
            return -EFAULT;
        }
        else
        {
            int32 level = *((int32 *)arg);
            if (!LOG_LEVEL_VALID(level))
            {
                DB_ERR("Invalid log level.");
                return -EFAULT;
            }
            s_klog_level = level;
        }
        break;
    case LOGCMD_GET_LEVEL:
        if (0 == arg)
        {
            DB_ERR("parameter arg is NULL.");
            return -EFAULT;
        }
        else
            *((int32 *)arg) = s_klog_level;
        break;
    case LOGCMD_LOG_ON:
        s_klog_on = TRUE;
        break;
    case LOGCMD_LOG_OFF:
        s_klog_on = FALSE;
        break;
    case LOGCMD_LOG_STATUS:
        if (0 == arg)
        {
            DB_ERR("parameter arg is NULL.");
            return -EFAULT;
        }
        else
            *((int32 *)arg) = TRUE == s_klog_on ? 1 : 0;
        break;
    default:
        DB_ERR("Undefined log cmd(%d).", cmd);
        return -EFAULT;
    }
    return 0;
}

static const struct file_operations s_klog_fops = {
    .owner          = THIS_MODULE,
    .open           = klog_open,
    .release        = klog_close,
    .read           = klog_read,
    .write          = klog_write,
    .poll           = klog_poll,
    .unlocked_ioctl = klog_ioctl,
};
//static int32 s_klog_major = 0;

static struct miscdevice s_klog_misc_device = {
    .minor  = MISC_DYNAMIC_MINOR,
    .name   = "klog",
    .fops   = &s_klog_fops,
};

static int32 __init klog_init(void)
{
    int32 ret = misc_register(&s_klog_misc_device);
    if (0 != ret)
    {
        DB_ERR("Kernel-Log Module init fail!!");
        return -EIO;
    }
    DB_INF("Kernel-Log Module init successfully.");
    spinlock_init(&s_klog_lock);
    return 0;
}

static void __exit klog_exit(void)
{
    buffer_t *buf = NULL;
    misc_deregister(&s_klog_misc_device);
    spinlock_lock(&s_klog_lock);
    while (NULL != sp_klog_used_buf_head)
    {
        buf = sp_klog_used_buf_head;
        sp_klog_used_buf_head = sp_klog_used_buf_head->next;
        klog_buf_free(buf);
    }
    sp_klog_used_buf_tail = NULL;
    while (NULL != sp_klog_free_buf_head)
    {
        buf = sp_klog_free_buf_head;
        sp_klog_free_buf_head = sp_klog_free_buf_head->next;
        klog_buf_free(buf);
    }
    sp_klog_free_buf_tail = NULL;
    spinlock_unlock(&s_klog_lock);
    spinlock_destroy(&s_klog_lock);
    DB_INF("Kernel-Log Module remove successfully.");
}
module_init(klog_init);
module_exit(klog_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zxc");
MODULE_DESCRIPTION("This module is a Kernel-Log Module for export kernel log to application and save it.");
