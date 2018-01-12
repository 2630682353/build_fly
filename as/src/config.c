#include "config.h"
//#include "type.h"
#include "message.h"
#include "debug.h"
#include "advertising.h"
#include "authenticated.h"
#include "blacklist.h"
#include "def.h"

#include <linux/kthread.h>
#include <linux/delay.h>

typedef struct advertising_cfg_st{
    uint32 id;
    int32 type;
    int8 url[URL_SIZE];
}advertising_cfg_t;

static inline int32 config_advertising_add(advertising_cfg_t *cfg)
{
    advertising_t ads;
    DB_PARAM("advertising: id[%u],type[%d],url[%s].", cfg->id, cfg->type, cfg->url);
    bzero(&ads, sizeof(ads));
    ads.id = cfg->id;
    ads.type = cfg->type;
    memcpy(ads.url, cfg->url, sizeof(ads.url));
    return advertising_add(&ads);
}

static inline void config_advertising_del(advertising_cfg_t *cfg)
{
    advertising_t *ads = advertising_search(cfg->id, cfg->type);
    DB_PARAM("advertising: id[%u],type[%d],url[%s].", cfg->id, cfg->type, cfg->url);
    if (NULL != ads)
    {
        advertising_put(ads);
        advertising_del(ads);
    }
}

static inline int32 config_advertising_policy_set(advertising_policy_t *policy)
{
    DB_PARAM("advertising-policy: policy[%d], option[%d], type[%d], time-interval[%llu], flow-interval[%llu].", 
        policy->policy, policy->option, policy->type, policy->time_interval, policy->flow_interval);
    return advertising_policy_set(policy);
}

static inline int32 config_advertising_policy_query(void *obuf,
                                                    int32 *olen)
{
    return advertising_policy_query_all(obuf, olen);
}

static inline int32 config_blacklist_add(const uint8 *mac)
{
    blacklist_t black;
    DB_PARAM("mac["MACSTR"]", MAC2STR(mac));
    bzero(&black, sizeof(black));
    memcpy(black.mac, mac, sizeof(black.mac));
    return blacklist_add(&black);
}

static inline void config_blacklist_del(const uint8 *mac)
{
    blacklist_t *black = blacklist_search(mac);
    DB_PARAM("mac["MACSTR"]", MAC2STR(mac));
    if (NULL != black)
    {
        blacklist_put(black);
        blacklist_del(black);
    }
}

typedef struct authenticated_cfg_st{
    uint32 ipaddr;
    uint8 mac[HWADDR_SIZE];
    int8 acct_status;   /*0:none; 1:accounting*/
    int8 acct_policy;   /*1:accounting by time; 2:accounting by flow; 3(1&2):accounting by time and flow*/
    uint64 total_seconds;
    uint64 total_flows;
}authenticated_cfg_t;

static inline int32 config_authenticated_add(authenticated_cfg_t *cfg)
{
    authenticated_t auth;
    DB_PARAM("mac["MACSTR"], acct_status:%d, acct_policy:%d, total_seconds:%llu, total_flows:%llu",
        MAC2STR(cfg->mac), cfg->acct_status, cfg->acct_policy, cfg->total_seconds, cfg->total_flows);
    bzero(&auth, sizeof(auth));
    memcpy(auth.mac, cfg->mac, sizeof(auth.mac));
    auth.ipaddr = cfg->ipaddr;
    auth.acct.status = (0 == cfg->acct_status) ? ACCT_STATUS_NONE : ACCT_STATUS_ACCTOUNTING;
    if (ACCT_STATUS_ACCTOUNTING == auth.acct.status)
    {
        if (1 == cfg->acct_policy)
            auth.acct.policy = ACCT_POLICY_BY_TIME;
        else if (2 == cfg->acct_policy)
            auth.acct.policy = ACCT_POLICY_BY_FLOW;
        else if (3 == cfg->acct_policy)
            auth.acct.policy = ACCT_POLICY_BY_FLOW | ACCT_POLICY_BY_TIME;

        auth.acct.valid_time = cfg->total_seconds;
        auth.acct.valid_flow = cfg->total_flows;
    }
    return authenticated_add(&auth);
}

static inline void config_authenticated_del(const uint8 *mac)
{
    authenticated_t *auth = authenticated_search(mac);
    DB_PARAM("mac["MACSTR"].",MAC2STR(mac));
    if (NULL != auth)
    {
        authenticated_put(auth);
        authenticated_del(auth);
    }
}

static int32 config_handle(const int32 cmd, 
                           void *ibuf, 
                           int32 ilen, 
                           void *obuf, 
                           int32 *olen)
{
    int32 ret = -1;
    switch (cmd)
    {
    case MSG_CMD_AS_AUTHENTICATED_ADD:
        {
            authenticated_cfg_t *auth_cfg = (authenticated_cfg_t *)ibuf;
            if (ilen < sizeof(*auth_cfg))
            {
                DB_ERR("ilen(%d) < sizeof(*auth_cfg)(%d). cmd(0x%x).", ilen, sizeof(*auth_cfg), cmd);
                *olen = snprintf(obuf, *olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                                ilen, sizeof(*auth_cfg), cmd);
                return ERR_CODE_PARAMETER;
                
            }
            ret = config_authenticated_add(auth_cfg);
            if (0 != ret)
            {
                DB_ERR("config_authenticated_add() fail. hwaddr[" MACSTR "].", MAC2STR(auth_cfg->mac));
                *olen = snprintf(obuf, *olen, "Add authenticated user fail. cmd[0x%x], hwaddr[" MACSTR "].", 
                    cmd, MAC2STR(auth_cfg->mac));
                return ERR_CODE_OPERATE_ADD;
            }
            *olen = 0;
            return SUCCESS;
        }
    case MSG_CMD_AS_AUTHENTICATED_DELETE:
        {
            uint8 *mac = (uint8 *)ibuf;
            if (ilen < HWADDR_SIZE)
            {
                DB_ERR("ilen(%d) < HWADDR_SIZE(%d). cmd(0x%x).", ilen, HWADDR_SIZE, cmd);
                *olen = snprintf(obuf, *olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                                ilen, HWADDR_SIZE, cmd);
                return ERR_CODE_PARAMETER;
            }
            config_authenticated_del(mac);
            *olen = 0;
            return SUCCESS;
        }
    case MSG_CMD_AS_AUTHENTICATED_QUERY:
        break;
    case MSG_CMD_AS_BLACKLIST_ADD:
        {
            uint8 *mac = (uint8 *)ibuf;
            if (ilen < HWADDR_SIZE)
            {
                DB_ERR("ilen(%d) < HWADDR_SIZE(%d). cmd(0x%x).", ilen, HWADDR_SIZE, cmd);
                *olen = snprintf(obuf, *olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                                ilen, HWADDR_SIZE, cmd);
                return ERR_CODE_PARAMETER;
            }
            ret = config_blacklist_add(mac);
            if (0 != ret)
            {
                DB_ERR("config_blacklist_add() fail. cmd[0x%x], hwaddr[" MACSTR "].", cmd, MAC2STR(mac));
                *olen = snprintf(obuf, *olen, "Add blacklist user fail. cmd[0x%x], hwaddr[" MACSTR "].", cmd, MAC2STR(mac));
                return ERR_CODE_OPERATE_ADD;
            }
            *olen = 0;
            return SUCCESS;
        }
    case MSG_CMD_AS_BLACKLIST_DELETE:
        {
            uint8 *mac = (uint8 *)ibuf;
            if (ilen < HWADDR_SIZE)
            {
                DB_ERR("ilen(%d) < HWADDR_SIZE(%d). cmd(0x%x).", ilen, HWADDR_SIZE, cmd);
                *olen = snprintf(obuf, *olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                                ilen, HWADDR_SIZE, cmd);
                return ERR_CODE_PARAMETER;
            }
            config_blacklist_del(mac);
            *olen = 0;
            return SUCCESS;
        }
    case MSG_CMD_AS_BLACKLIST_QUERY:
        break;
    case MSG_CMD_AS_ADVERTISING_ADD:
        {
            advertising_cfg_t *ads_cfg = (advertising_cfg_t *)ibuf;
            if (ilen < sizeof(*ads_cfg))
            {
                DB_ERR("ilen(%d) < sizeof(*ads_cfg)(%d). cmd(0x%x).", ilen, sizeof(*ads_cfg), cmd);
                *olen = snprintf(obuf, *olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                                ilen, sizeof(*ads_cfg), cmd);
                return ERR_CODE_PARAMETER;
                
            }
            ret = config_advertising_add(ads_cfg);
            if (0 != ret)
            {
                DB_ERR("config_advertising_add() fail. cmd[0x%x], id[%u], type[%d], url[%s].", 
                        cmd, ads_cfg->id, ads_cfg->type, ads_cfg->url);
                *olen = snprintf(obuf, *olen, "Add advertising fail. cmd[0x%x], id[%u], type[%d], url[%s].", 
                                cmd, ads_cfg->id, ads_cfg->type, ads_cfg->url);
                return ERR_CODE_OPERATE_ADD;
            }
            *olen = 0;
            return SUCCESS;
        }
    case MSG_CMD_AS_ADVERTISING_DELETE:
        {
            advertising_cfg_t *ads_cfg = (advertising_cfg_t *)ibuf;
            if (ilen < sizeof(*ads_cfg))
            {
                DB_ERR("ilen(%d) < sizeof(*ads_cfg)(%d). cmd(0x%x).", ilen, sizeof(*ads_cfg), cmd);
                *olen = snprintf(obuf, *olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                                ilen, sizeof(*ads_cfg), cmd);
                return ERR_CODE_PARAMETER;
                
            }
            config_advertising_del(ads_cfg);
            *olen = 0;
            return SUCCESS;
        }
    case MSG_CMD_AS_ADVERTISING_QUERY:
        break;
    case MSG_CMD_AS_ADVERTISING_POLICY_SET:
        {
            advertising_policy_t *policy = (advertising_policy_t *)ibuf;
            if (ilen < sizeof(*policy))
            {
                DB_ERR("ilen(%d) < sizeof(*policy)(%d). cmd(0x%x).", ilen, sizeof(*policy), cmd);
                *olen = snprintf(obuf, *olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                                ilen, sizeof(*policy), cmd);
                return ERR_CODE_PARAMETER;
            }
            if (0 != config_advertising_policy_set(policy))
            {
                DB_ERR("config_advertising_policy_set() call fail. cmd[0x%x].", cmd);
                *olen = snprintf(obuf, *olen,  "Set Advertising Policy fail. cmd[0x%x].", cmd);
                return ERR_CODE_OPERATE_ADD;
            }
            *olen = 0;
            return SUCCESS;
        }
    case MSG_CMD_AS_ADVERTISING_POLICY_QUERY:
        if (0 != config_advertising_policy_query(obuf, olen))
        {
            DB_ERR("config_advertising_policy_query() call fail. cmd[0x%x].", cmd);
            *olen = snprintf(obuf, *olen, "Query Advertising Policy fail. cmd[0x%x].", cmd);
            return ERR_CODE_OPERATE_QUERY;
        }
        return SUCCESS;
    case MSG_CMD_AS_PORTAL_URL_SET:
        break;
    case MSG_CMD_AS_PORTAL_URL_QUERY:
        break;
    case MSG_CMD_AS_INNER_INTERFACE_SET:
        break;
    case MSG_CMD_AS_INNER_INTERFACE_QUERY:
        break;
    case MSG_CMD_AS_OUTER_INTERFACE_SET:
        break;
    case MSG_CMD_AS_OUTER_INTERFACE_QUERY:
        break;
    default:
        *olen = snprintf(obuf, *olen, "Invalid cmd[0x%x].", cmd);
        return ERR_CODE_NONECMD;
        break;
    }
    *olen = snprintf(obuf, *olen, "Unsupported cmd[0x%x] now.", cmd);
    return ERR_CODE_UNSUPPORTED;
}

typedef struct event_info{
    struct list_head list;
    int32 cmd;
    uint8 *data;
    uint32 dlen;
}event_info_t;
static LIST_HEAD(s_list_event);
static spinlock_t s_spinlock_list_event;
static struct task_struct *sp_kthd = NULL;

static int32 config_event_kthread_func(void *data)
{
    event_info_t *event = NULL;
    while (!kthread_should_stop())
    {
        spinlock_lock(&s_spinlock_list_event);
        if (!list_empty(&s_list_event))
        {
            event = list_first_entry(&s_list_event, event_info_t, list);
            list_del(&event->list);
        }
        spinlock_unlock(&s_spinlock_list_event);
        if (likely(NULL == event))
            msleep_interruptible(100);
        else
        {
            int32 ret = msg_send_syn(event->cmd, event->data, event->dlen, NULL, NULL);
            if (unlikely(SUCCESS != ret))
                DB_ERR("msg_send_syn() call fail. cmd[%d], errno[%d].", event->cmd, ret);
            if (NULL != event->data)
                free(event->data);
            free(event);
            event = NULL;
        }
    }
    return 0;
}

void config_authenticated_timeout(const int8 *mac)
{
    event_info_t *event = malloc(sizeof(*event));
    event->dlen = HWADDR_SIZE;
    event->data = malloc(event->dlen);
    memcpy(event->data, mac, event->dlen);
    event->cmd = MSG_CMD_RADIUS_AUTH_TIMEOUT;
    spinlock_lock(&s_spinlock_list_event);
    list_add_tail(&event->list, &s_list_event);
    spinlock_unlock(&s_spinlock_list_event);
}

int32 config_init(void)
{
    int32 cmd = MSG_CMD_AS_START;
    int32 ret = -1;
    while (cmd < MSG_CMD_AS_END)
    {
        ret = msg_cmd_register(cmd, config_handle);
        if (0 != ret)
        {
            DB_ERR("msg_cmd_register() fail. cmd:%d.", cmd);
            goto out;
        }
        ++cmd;
    }
    sp_kthd = kthread_run(config_event_kthread_func, NULL, "cfg-event-kthread");
    if (unlikely(NULL == sp_kthd))
        goto out;
    ret = 0;
out:
    if (0 != ret)
    {
        while (cmd >= MSG_CMD_AS_START)
        {
            msg_cmd_unregister(cmd);
            --cmd;
        }
    }
    return ret;
}

void config_final(void)
{
    int32 cmd = MSG_CMD_AS_END - 1;
    while (cmd >= MSG_CMD_AS_START)
    {
        msg_cmd_unregister(cmd);
        --cmd;
    }
    kthread_stop(sp_kthd);
}