#include "dpi-hook.h"
#include "rwlock.h"
#include "debug.h"
#include "def.h"

static struct list_head s_dpi_hooks[DPI_HOOK_MAXNUM][DPI_DIRECTION_MAXNUM];
static rwlock_t s_rwlock_dpi_hooks;
static BOOL s_dpi_inited = FALSE;

void dpi_hook_init(void)
{
    int32 i,j;
    if (unlikely(TRUE == s_dpi_inited))
        return;
    for (i=0; i<DPI_HOOK_MAXNUM; ++i)
    {
        for (j=0; j<DPI_DIRECTION_MAXNUM; ++j)
            INIT_LIST_HEAD(&s_dpi_hooks[i][j]);
    }
    rwlock_init(&s_rwlock_dpi_hooks);
    s_dpi_inited = TRUE;
}

void dpi_hook_destroy(void)
{
    int32 i,j;
    dpi_hook_ops_t *elem;
    if (unlikely(TRUE != s_dpi_inited))
        return;
    s_dpi_inited = FALSE;
    rwlock_wrlock_bh(&s_rwlock_dpi_hooks);
    for (i=0; i<DPI_HOOK_MAXNUM; ++i)
    {
        for (j=0; j<DPI_DIRECTION_MAXNUM; ++j)
        {
            while (!list_empty(&s_dpi_hooks[i][j]))
            {
                elem = list_first_entry(&s_dpi_hooks[i][j], dpi_hook_ops_t, list);
                list_del(&elem->list);
            }
            INIT_LIST_HEAD(&s_dpi_hooks[i][j]);
        }
    }
    rwlock_wrunlock_bh(&s_rwlock_dpi_hooks);
    rwlock_destroy(&s_rwlock_dpi_hooks);
}

int32 dpi_register_hook(dpi_hook_ops_t *ops)
{
	dpi_hook_ops_t *elem;
    struct list_head *head;
    if (unlikely(TRUE != s_dpi_inited))
        return -1;
    if (unlikely(NULL == ops
        || !DPI_DIRECTION_VALID(ops->direction) 
        || !DPI_HOOKNUM_VALID(ops->hooknum)))
        return -1;
    head = &s_dpi_hooks[ops->hooknum][ops->direction];
    rwlock_wrlock_bh(&s_rwlock_dpi_hooks);
    list_for_each_entry(elem, &s_dpi_hooks[ops->hooknum][ops->direction], list) 
    {
        if (ops->priority < elem->priority)
        {
            head = &elem->list;
            break;
        }
    }
    atomic_set(&ops->refcnt, 1);
    list_add_tail(&ops->list, head);
    rwlock_wrunlock_bh(&s_rwlock_dpi_hooks);
    return 0;
}
EXPORT_SYMBOL(dpi_register_hook);

void dpi_unregister_hook(dpi_hook_ops_t *ops)
{
    if (unlikely(TRUE != s_dpi_inited))
        return;
    if (unlikely(NULL == ops))
        return;
    if (likely(atomic_read(&ops->refcnt) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&ops->refcnt)))
        return;
    rwlock_wrlock_bh(&s_rwlock_dpi_hooks);
    list_del(&ops->list);
    rwlock_wrunlock_bh(&s_rwlock_dpi_hooks);
}
EXPORT_SYMBOL(dpi_unregister_hook);

int32 dpi_register_hooks(dpi_hook_ops_t *ops,
                         const uint32 num)
{
    uint32 i;
    int32 err = 0;
    for (i = 0; i < num; i++) 
    {
        err = dpi_register_hook(&ops[i]);
        if (err)
            goto err;
    }
    return err;
err:
    if (i > 0)
        dpi_unregister_hooks(ops, i);
    return err;
}
EXPORT_SYMBOL(dpi_register_hooks);

void dpi_unregister_hooks(dpi_hook_ops_t *ops,
                          const uint32 num)
{
    uint32 i = 0;
    while (i < num)
        dpi_unregister_hook(&ops[i++]);
}
EXPORT_SYMBOL(dpi_unregister_hooks);
/*必须在rcu_read_lock()或rcu_read_lock_bh()保护下使用*/
void dpi_hook(struct sk_buff *skb,
              const int32 hooknum,
              const int32 direction)
{
    dpi_hook_ops_t *elem;
    if (unlikely(TRUE != s_dpi_inited))
        return;
    rwlock_rdlock(&s_rwlock_dpi_hooks);
    list_for_each_entry(elem, &s_dpi_hooks[hooknum][direction], list)
        elem->hook(skb, elem->data);
    rwlock_rdunlock(&s_rwlock_dpi_hooks);
}

static struct proc_dir_entry *sp_proc_dpi_hook = NULL;
#define PROC_DPI_HOOK   "dpi_hook"

typedef struct {
    struct list_head *head;
    uint32 index_hooknum;
    uint32 index_direction;
}dpi_hook_proc_data_t;

static ssize_t dpi_hook_read(struct file *file, 
                             int8 __user *buf, 
                             size_t size, 
                             loff_t *ppos)
{
    int8 tmp[512];
    int32 len;
    int32 copyed = 0;
    dpi_hook_proc_data_t *data = (dpi_hook_proc_data_t *)file->private_data;
    dpi_hook_ops_t *elem;
    uint32 index = 0;
    while (likely(copyed < size))
    {
        if (data->index_direction >= DPI_DIRECTION_MAXNUM || data->index_hooknum >= DPI_HOOK_MAXNUM)
            break;
        if (data->head->next == &s_dpi_hooks[data->index_hooknum][data->index_direction])
        {
            ++data->index_direction;
            if (data->index_direction >= DPI_DIRECTION_MAXNUM)
            {
                ++data->index_hooknum;
                data->index_direction = 0;
            }
            if (data->index_hooknum >= DPI_HOOK_MAXNUM)
                break;
            data->head = &s_dpi_hooks[data->index_hooknum][data->index_direction];
            index = 0;
            continue;
        }
        elem = list_first_entry(data->head, dpi_hook_ops_t, list);
        len = sprintf(tmp, "[%u.%u.%u][%p] hook[%p],priority[%d],direction[%d],hooknum[%d],data[%p].\n", 
                    data->index_hooknum+1, data->index_direction+1, index+1, &elem->list, elem->hook, elem->priority, 
                    elem->direction, elem->hooknum, elem->data);
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        data->head = &elem->list;
        ++index;
    }
    *ppos += copyed;
    return copyed;
}

static int32 dpi_hook_proc_open(struct inode *inode, 
                                struct file *file)
{
    dpi_hook_ops_t *elem;
    uint32 index_hooknum, index_direction;
    dpi_hook_proc_data_t *data = malloc(sizeof(*data));
    if (unlikely(NULL == data))
        return -EIO;
    bzero(data, sizeof(*data));
    data->head = &s_dpi_hooks[0][0];
    data->index_hooknum = 0;
    data->index_direction = 0;
    file->private_data = (void *)data;
    rwlock_rdlock_bh(&s_rwlock_dpi_hooks);
    for (index_hooknum=0; index_hooknum<DPI_HOOK_MAXNUM; ++index_hooknum)
    {
        for (index_direction=0; index_direction<DPI_DIRECTION_MAXNUM; ++index_direction)
        {
            if (list_empty(&s_dpi_hooks[index_hooknum][index_direction]))
                continue;
            list_for_each_entry(elem, &s_dpi_hooks[index_hooknum][index_direction], list)
                atomic_inc(&elem->refcnt);
        }
    }
    rwlock_rdunlock_bh(&s_rwlock_dpi_hooks);
    return 0;
}

static int32 dpi_hook_proc_close(struct inode *inode, 
                                 struct file *file)
{
    dpi_hook_ops_t *elem, *elem_next;
    uint32 index_hooknum, index_direction;
    for (index_hooknum=0; index_hooknum<DPI_HOOK_MAXNUM; ++index_hooknum)
    {
        for (index_direction=0; index_direction<DPI_DIRECTION_MAXNUM; ++index_direction)
        {
            if (list_empty(&s_dpi_hooks[index_hooknum][index_direction]))
                continue;
            list_for_each_entry_safe(elem, elem_next, &s_dpi_hooks[index_hooknum][index_direction], list)
                dpi_unregister_hook(elem);
        }
    }
    free(file->private_data);
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_dpi_hook_fileops = {
    .owner      = THIS_MODULE,
    .read       = dpi_hook_read,
    .open       = dpi_hook_proc_open,
    .release    = dpi_hook_proc_close
};
int32 dpi_hook_proc_init(struct proc_dir_entry *parent)
{
    struct proc_dir_entry *entry = proc_create(PROC_DPI_HOOK, 0, parent, &s_dpi_hook_fileops);
    if (unlikely(NULL == entry))
    {
        DB_ERR("proc_create(%s) fail!!", PROC_DPI_HOOK);
        return -1;
    }
    sp_proc_dpi_hook = entry;
    return 0;
}

void dpi_hook_proc_destroy(struct proc_dir_entry *parent)
{
    if (unlikely(NULL != sp_proc_dpi_hook))
    {
        remove_proc_entry(PROC_DPI_HOOK, parent);
        sp_proc_dpi_hook = NULL;
    }
}
