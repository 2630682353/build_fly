#ifndef __ADVERTISING_H__
#define __ADVERTISING_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include "type.h"
#include "def.h"

/*advertising type*/
typedef enum ads_type_en{
    ADS_TYPE_PUSH   = 0x00, /*push advertising*/
    ADS_TYPE_EMBED  = 0x01  /*embed advertising*/
}ads_type_e;

typedef struct advertising_st{
    struct list_head list;
    uint32 id;
    int32 type; /*Values from enum "ads_type_e"*/
    atomic_t refcnt;
    uint8 url[URL_SIZE];
}advertising_t;


/*advertising policy*/
typedef enum ads_policy_en{
    ADS_POLICY_NONE           = 0x00, /*none*/
    ADS_POLICY_TIME_INTERVAL  = 0x01, /*time interval*/
    ADS_POLICY_FLOW_INTERVAL  = 0x02, /*flow interval*/
    ADS_POLICY_EVERYTIME      = 0x04  /*everytime. valid when ads->type is ADS_TYPE_EMBED*/
}ads_policy_e;
/*advertising option*/
typedef enum ads_option_en{
    ADS_OPTION_RANDOM   = 0x00, /*random*/
    ADS_OPTION_LOOPING  = 0x01  /*looping*/
}ads_option_e;

typedef struct advertising_policy_st{
    int32 policy;
    int32 option;
    int32 type;
    uint64 time_interval;
    uint64 flow_interval;
}advertising_policy_t;

int32 advertising_init(const uint32 max_push,
                       const uint32 max_embed);
void advertising_destroy(void);
int32 advertising_add(advertising_t *ads);
void advertising_del(advertising_t *ads);
advertising_t *advertising_get(advertising_t *ads);
void advertising_put(advertising_t *ads);
advertising_t *advertising_search(const uint32 id,
                                  const int32 type);
int32 advertising_redirect(struct sk_buff *skb,
                           uint32 *latestid,
                           int32 type);
int32 advertising_policy_set(const advertising_policy_t *policy);
advertising_policy_t *advertising_policy_get(const int32 type);
int32 advertising_policy_query_all(void *obuf,
                                   int32 *olen);
int32 advertising_proc_init(struct proc_dir_entry *parent);
void advertising_proc_destroy(struct proc_dir_entry *parent);

#ifdef  __cplusplus
}
#endif

#endif /*__ADVERTISING_H__*/
