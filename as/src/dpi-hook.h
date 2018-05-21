#ifndef __DPI_HOOK_H__
#define __DPI_HOOK_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "type.h"

enum {
    DPI_DIRECTION_UPLINK    = 0,
    DPI_DIRECTION_DOWNLINK  = 1,
    
    DPI_DIRECTION_MAXNUM    = 2
};
#define DPI_DIRECTION_VALID(dir)    ((dir)>=DPI_DIRECTION_UPLINK && (dir)<DPI_DIRECTION_MAXNUM)
enum {
    DPI_HOOK_BLACKLIST      = 0,
    DPI_HOOK_WHITELIST      = 1,
    DPI_HOOK_AUTHENTICATED  = 2,
    
    DPI_HOOK_MAXNUM         = 3
};
#define DPI_HOOKNUM_VALID(hook)     ((hook)>=DPI_HOOK_BLACKLIST && (hook)<DPI_HOOK_MAXNUM)
typedef struct dpi_hook_ops_st{
    struct list_head list;
    atomic_t refcnt;
    void (*hook)(struct sk_buff *skb, void *data);
    int32 priority;
    int32 direction;
    int32 hooknum;
    void *data;
}dpi_hook_ops_t;

void dpi_hook_init(void);
void dpi_hook_destroy(void);
/*必须在rcu_read_lock()或rcu_read_lock_bh()保护下使用*/
void dpi_hook(struct sk_buff *skb,
              const int32 hooknum,
              const int32 direction);
/*对外导出的接口*/
int32 dpi_register_hook(dpi_hook_ops_t *ops);
void dpi_unregister_hook(dpi_hook_ops_t *ops);
int32 dpi_register_hooks(dpi_hook_ops_t *ops,
                         const uint32 num);
void dpi_unregister_hooks(dpi_hook_ops_t *ops,
                          const uint32 num);
int32 dpi_hook_proc_init(struct proc_dir_entry *parent);
void dpi_hook_proc_destroy(struct proc_dir_entry *parent);

#ifdef  __cplusplus
}
#endif

#endif /*__DPI_HOOK_H__*/
