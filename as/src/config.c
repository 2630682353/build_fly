#include "config.h"
#include "message.h"
#include "debug.h"
#include "advertising.h"
#include "authenticated.h"
#include "blacklist.h"
#include "whitelist.h"
#include "def.h"
#include "portal.h"

#include <linux/kthread.h>
#include <linux/delay.h>

static void config_error(void *buf,
                         int32 *size,
                         int8 *fmt, ...)
{
    if (NULL != buf && NULL != size && *size > 0)
    {
        va_list va;
        va_start(va, fmt);
        *size = vsnprintf(buf, *size, fmt, va);
        va_end(va);
    }
}

typedef struct advertising_cfg_st{
    uint32 id;
    int32 type;
    int8 url[URL_SIZE];
}advertising_cfg_t;

static int32 config_advertising_add(const int32 cmd,
                                    void *ibuf,
                                    int32 ilen,
                                    void *obuf,
                                    int32 *olen)
{
    advertising_t ads;
    advertising_cfg_t *cfg;
    int32 ret;
    if (ilen < sizeof(*cfg))
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        return ERR_CODE_PARAMETER;
    }
    cfg = (advertising_cfg_t *)ibuf;
    DB_PARAM("advertising: id[%u],type[%s],url[%s].", cfg->id, ads_type_to_str(cfg->type), cfg->url);
    bzero(&ads, sizeof(ads));
    ads.id = cfg->id;
    ads.type = cfg->type;
    memcpy(ads.url, cfg->url, sizeof(ads.url));
    ret = advertising_add(&ads);
    if (0 != ret)
    {
        DB_ERR("config_advertising_add() fail. cmd[0x%x],id[%u],type[%d],url[%s].", 
                cmd, cfg->id, cfg->type, cfg->url);
        config_error(obuf, olen, "Add advertising fail. cmd[0x%x],id[%u],type[%s],url[%s].", 
                cmd, cfg->id, ads_type_to_str(cfg->type), cfg->url);
        return ERR_CODE_OPERATE_ADD;
    }
    *olen = 0;
    return SUCCESS;
}

static int32 config_advertising_del(const int32 cmd,
                                    void *ibuf,
                                    int32 ilen,
                                    void *obuf,
                                    int32 *olen)
{
    advertising_cfg_t *cfg;
    if (ilen < sizeof(*cfg))
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        return ERR_CODE_PARAMETER;
    }
    cfg = (advertising_cfg_t *)ibuf;
    DB_PARAM("advertising: id[%u],type[%s],url[%s].", cfg->id, ads_type_to_str(cfg->type), cfg->url);
    advertising_del_by_id_type(cfg->id, cfg->type);
    *olen = 0;
    return SUCCESS;
}

static int32 config_advertising_policy_set(const int32 cmd,
                                           void *ibuf,
                                           int32 ilen,
                                           void *obuf,
                                           int32 *olen)
{
    advertising_policy_t *policy = (advertising_policy_t *)ibuf;
    if (ilen < sizeof(*policy))
    {
        DB_ERR("ilen(%d) < sizeof(*policy)(%d). cmd(0x%x).", ilen, sizeof(*policy), cmd);
        config_error(obuf, olen, "Invalid parameter. Received data length(%d) < Expect data length(%d). cmd[0x%x].", 
                ilen, sizeof(*policy), cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("advertising-policy: policy[%s],option[%s],type[%s],"
        "time-interval[%llu],flow-interval[%llu].", 
        ads_policy_to_str(policy->policy), 
        ads_option_to_str(policy->option), 
        ads_type_to_str(policy->type), 
        policy->time_interval, policy->flow_interval);
    if (0 != advertising_policy_set(policy))
    {
        DB_ERR("advertising_policy_set() call fail. cmd[0x%x].", cmd);
        config_error(obuf, olen,  "Set Advertising Policy fail. cmd[0x%x].", cmd);
        return ERR_CODE_OPERATE_ADD;
    }
    *olen = 0;
    return SUCCESS;
}

static int32 config_advertising_policy_query(const int32 cmd,
                                             void *ibuf,
                                             int32 ilen,
                                             void *obuf,
                                             int32 *olen)
{
    int32 ret;
    ret = advertising_policy_query_all(obuf, olen);
    if (0 != ret)
    {
        DB_ERR("config_advertising_policy_query() call fail. cmd[0x%x].", cmd);
        config_error(obuf, olen, "Query Advertising Policy fail. cmd[0x%x].", cmd);
        return ERR_CODE_OPERATE_QUERY;
    }
    return SUCCESS;
}

static int32 config_blacklist_add(const int32 cmd,
                                  void *ibuf,
                                  int32 ilen,
                                  void *obuf,
                                  int32 *olen)
{
    blacklist_t black;
    uint8 *mac = (uint8 *)ibuf;
    int32 ret;
    if (ilen < HWADDR_SIZE)
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("hwaddr["MACSTR"].", MAC2STR(mac));
    bzero(&black, sizeof(black));
    memcpy(black.mac, mac, sizeof(black.mac));
    ret = blacklist_add(&black);
    if (0 != ret)
    {
        DB_ERR("blacklist_add() fail. hwaddr["MACSTR"].", MAC2STR(mac));
        config_error(obuf, olen, "Add user to blacklist fail. hwaddr["MACSTR"],cmd[0x%x].", 
            MAC2STR(mac), cmd);
        return ERR_CODE_OPERATE_ADD;
    }
    *olen = 0;
    return SUCCESS;
}

static int32 config_blacklist_del(const int32 cmd,
                                  void *ibuf,
                                  int32 ilen,
                                  void *obuf,
                                  int32 *olen)
{
    uint8 *mac = (uint8 *)ibuf;
    if (ilen < HWADDR_SIZE)
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("hwaddr["MACSTR"].", MAC2STR(mac));
    blacklist_del_by_mac(mac);
    *olen = 0;
    return SUCCESS;
}

static int32 config_whitelist_add(const int32 cmd,
                                  void *ibuf,
                                  int32 ilen,
                                  void *obuf,
                                  int32 *olen)
{
    whitelist_t white;
    uint8 *mac = (uint8 *)ibuf;
    int32 ret;
    if (ilen < HWADDR_SIZE)
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("hwaddr["MACSTR"].", MAC2STR(mac));
    bzero(&white, sizeof(white));
    memcpy(white.mac, mac, sizeof(white.mac));
    ret = whitelist_add(&white);
    if (0 != ret)
    {
        DB_ERR("whitelist_add() fail. hwaddr["MACSTR"].", MAC2STR(mac));
        config_error(obuf, olen, "Add user to whitelist fail. hwaddr["MACSTR"],cmd[0x%x].", 
            MAC2STR(mac), cmd);
        return ERR_CODE_OPERATE_ADD;
    }
    *olen = 0;
    return SUCCESS;
}

static int32 config_whitelist_del(const int32 cmd,
                                  void *ibuf,
                                  int32 ilen,
                                  void *obuf,
                                  int32 *olen)
{
    uint8 *mac = (uint8 *)ibuf;
    if (ilen < HWADDR_SIZE)
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("hwaddr["MACSTR"].", MAC2STR(mac));
    whitelist_del_by_mac(mac);
    *olen = 0;
    return SUCCESS;
}


typedef struct authenticated_cfg_st{
    uint32 ipaddr;
    uint8 mac[HWADDR_SIZE];
    int8 acct_status;   /*0:none; 1:accounting*/
    int8 acct_policy;   /*1:accounting by time; 2:accounting by flow; 3(1|2):accounting by time and flow*/
    uint64 total_seconds;
    uint64 total_flows;
}authenticated_cfg_t;

static int32 config_authenticated_add(const int32 cmd,
                                      void *ibuf,
                                      int32 ilen,
                                      void *obuf,
                                      int32 *olen)
{
    authenticated_cfg_t *cfg = NULL;
    authenticated_t auth;
    int32 ret;
    if (NULL == ibuf || ilen < sizeof(*cfg))
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        return ERR_CODE_PARAMETER;
    }
    cfg = (authenticated_cfg_t *)ibuf;
    DB_PARAM("hwaddr["MACSTR"],ipaddr["IPSTR"],acct_status[%s],acct_policy[%s],total_seconds[%llu],total_flows[%llu].",
        MAC2STR(cfg->mac), IP2STR(htonl(cfg->ipaddr)), acct_status_to_str(cfg->acct_status), acct_policy_to_str(cfg->acct_policy), 
        cfg->total_seconds, cfg->total_flows);
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
    ret = authenticated_add(&auth);
    if (0 != ret)
    {
        DB_ERR("config_authenticated_add() fail. hwaddr["MACSTR"].", MAC2STR(cfg->mac));
        config_error(obuf, olen, "Add authenticated user fail. hwaddr["MACSTR"],cmd[0x%x].", 
            MAC2STR(cfg->mac), cmd);
        return ERR_CODE_OPERATE_ADD;
    }
    *olen = 0;
    return SUCCESS;
}

static int32 config_authenticated_del(const int32 cmd,
                                      void *ibuf,
                                      int32 ilen,
                                      void *obuf,
                                      int32 *olen)
{
    uint8 *mac = (uint8 *)ibuf;
    if (ilen < HWADDR_SIZE)
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, HWADDR_SIZE, cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("hwaddr["MACSTR"].", MAC2STR(mac));
    authenticated_del_by_mac(mac);
    *olen = 0;
    return SUCCESS;
}

typedef struct portal_cfg_st{
    int32 apply;/*0:interface; 1:vlan*/
    union {
        int8 ifname[IFNAME_SIZE];
        uint16 vlan_id;
    };
    int8 url[URL_SIZE];
}portal_cfg_t;

static int32 config_portal_add(const int32 cmd,
                               void *ibuf,
                               int32 ilen,
                               void *obuf,
                               int32 *olen)
{
    portal_cfg_t *cfg;
    int32 ret = -1;
    if (NULL == ibuf || ilen < sizeof(*cfg))
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        return ERR_CODE_PARAMETER;
    }
    cfg = (portal_cfg_t *)ibuf;
    if (0 == cfg->apply) /*apply to interface*/
    {
        DB_PARAM("apply[%d],ifname[%s],url[%s].", cfg->apply, cfg->ifname, cfg->url);
        ret = portal_interface_add(cfg->ifname, cfg->url);
        if (0 != ret)
        {
            DB_ERR("portal_interface_add() fail. ifname[%s],url[%s],cmd[0x%x].", cfg->ifname, cfg->url, cmd);
            config_error(obuf, olen, "Apply portal '%s' to the interface '%s' failure. cmd[0x%x].", cfg->url, cfg->ifname, cmd);
            return ERR_CODE_OPERATE_ADD;
        }
    }
    else if (1 == cfg->apply) /*apply to vlan*/
    {
        DB_PARAM("apply[%d],vlan_id[%u],url[%s].", cfg->apply, cfg->vlan_id, cfg->url);
        ret = portal_vlan_add(cfg->vlan_id, cfg->url);
        if (0 != ret)
        {
            DB_ERR("portal_vlan_add() fail. vlan_id[%u],url[%s],cmd[0x%x].", cfg->vlan_id, cfg->url, cmd);
            config_error(obuf, olen, "Apply portal '%s' to the vlan '%u' failure. cmd[0x%x].", cfg->url, cfg->vlan_id, cmd);
            return ERR_CODE_OPERATE_ADD;
        }
    }
    else
    {
        DB_ERR("Undefined portal config apply-type(%d). cmd[0x%x].", cfg->apply, cmd);
        config_error(obuf, olen, "Undefined portal config apply-type(%d). cmd[0x%x].", cfg->apply, cmd);
        return ERR_CODE_PARAMETER;
    }
    *olen = 0;
    return SUCCESS;
}

static int32 config_portal_del(const int32 cmd,
                               void *ibuf,
                               int32 ilen,
                               void *obuf,
                               int32 *olen)
{
    portal_cfg_t *cfg;
    if (NULL == ibuf || ilen < sizeof(*cfg))
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*cfg), cmd);
        return ERR_CODE_PARAMETER;
    }
    cfg = (portal_cfg_t *)ibuf;
    if (0 == cfg->apply) /*apply to interface*/
    {
        DB_PARAM("apply[%d],ifname[%s].", cfg->apply, cfg->ifname, cfg->url);
        portal_interface_del_by_ifname(cfg->ifname);
    }
    else if (1 == cfg->apply) /*apply to vlan*/
    {
        DB_PARAM("apply[%d],vlan_id[%u].", cfg->apply, cfg->vlan_id);
        portal_vlan_del_by_vlanid(cfg->vlan_id);
    }
    else
    {
        DB_ERR("Undefined portal config apply-type(%d). cmd[0x%x].", cfg->apply, cmd);
        config_error(obuf, olen, "Undefined portal config apply-type(%d). cmd[0x%x].", cfg->apply, cmd);
        return ERR_CODE_PARAMETER;
    }
    *olen = 0;
    return SUCCESS;
}

static struct {
    int32 cmd;
    int32 (*handle)(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen);
} s_config_handles[] = {
        {MSG_CMD_AS_AUTHENTICATED_ADD,          config_authenticated_add},
        {MSG_CMD_AS_AUTHENTICATED_DELETE,       config_authenticated_del},
        {MSG_CMD_AS_BLACKLIST_ADD,              config_blacklist_add},
        {MSG_CMD_AS_BLACKLIST_DELETE,           config_blacklist_del},
        {MSG_CMD_AS_WHITELIST_ADD,              config_whitelist_add},
        {MSG_CMD_AS_WHITELIST_DELETE,           config_whitelist_del},
        {MSG_CMD_AS_ADVERTISING_ADD,            config_advertising_add},
        {MSG_CMD_AS_ADVERTISING_DELETE,         config_advertising_del},
        {MSG_CMD_AS_ADVERTISING_POLICY_SET,     config_advertising_policy_set},
        {MSG_CMD_AS_ADVERTISING_POLICY_QUERY,   config_advertising_policy_query},
        {MSG_CMD_AS_PORTAL_ADD,                 config_portal_add},
        {MSG_CMD_AS_PORTAL_DELETE,              config_portal_del}
};

static int32 config_handle(const int32 cmd, 
                           void *ibuf, 
                           int32 ilen, 
                           void *obuf, 
                           int32 *olen)
{
    int32 index;
#define MSG_CMD_AS_VALID(cmd)   ((cmd) >= MSG_CMD_AS_START && (cmd) < MSG_CMD_AS_END)
    if (!MSG_CMD_AS_VALID(cmd))
    {
        config_error(obuf, olen, "Invalid cmd[0x%x].", cmd);
        return ERR_CODE_NONECMD;
    }
    for (index = 0; index < ARRAY_SIZE(s_config_handles); ++index)
    {
        if (cmd == s_config_handles[index].cmd && NULL != s_config_handles[index].handle)
            return s_config_handles[index].handle(cmd, ibuf, ilen, obuf, olen);
    }
    config_error(obuf, olen, "Unsupported cmd[0x%x] now.", cmd);
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
static struct task_struct *sp_kthd_cfg = NULL;

static int32 config_event_kthread_func(void *data)
{
    event_info_t *event = NULL;
    int32 ret;
    while (!kthread_should_stop())
    {
        spinlock_lock_bh(&s_spinlock_list_event);
        if (list_empty(&s_list_event))
        {
            spinlock_unlock_bh(&s_spinlock_list_event);
            set_current_state(TASK_UNINTERRUPTIBLE);
            schedule();
            continue;
        }
        while (!list_empty(&s_list_event))
        {
            event = list_first_entry(&s_list_event, event_info_t, list);
            list_del(&event->list);
            spinlock_unlock_bh(&s_spinlock_list_event);
            ret = msg_send_syn(event->cmd, event->data, event->dlen, NULL, NULL);
            if (unlikely(SUCCESS != ret))
                DB_ERR("msg_send_syn() call fail. cmd[%d], errno[%d].", event->cmd, ret);
            if (NULL != event->data)
                free(event->data);
            free(event);
            event = NULL;
            spinlock_lock_bh(&s_spinlock_list_event);
        }
        spinlock_unlock_bh(&s_spinlock_list_event);
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
    if (NULL != sp_kthd_cfg && TASK_RUNNING != sp_kthd_cfg->state)
        wake_up_process(sp_kthd_cfg);
}

void config_authenticated_timeout_bh(const int8 *mac)
{
    event_info_t *event = malloc(sizeof(*event));
    event->dlen = HWADDR_SIZE;
    event->data = malloc(event->dlen);
    memcpy(event->data, mac, event->dlen);
    event->cmd = MSG_CMD_RADIUS_AUTH_TIMEOUT;
    spinlock_lock_bh(&s_spinlock_list_event);
    list_add_tail(&event->list, &s_list_event);
    spinlock_unlock_bh(&s_spinlock_list_event);
    if (NULL != sp_kthd_cfg && TASK_RUNNING != sp_kthd_cfg->state)
        wake_up_process(sp_kthd_cfg);
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
    sp_kthd_cfg = kthread_create(config_event_kthread_func, NULL, "kthd-cfg");
    if (unlikely(IS_ERR(sp_kthd_cfg)))
    {
        ret = PTR_ERR(sp_kthd_cfg);
        DB_ERR("kthread_create() call fail. errno[%d].", ret);
        sp_kthd_cfg = NULL;
        goto out;
    }
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
    kthread_stop(sp_kthd_cfg);
    while (cmd >= MSG_CMD_AS_START)
    {
        msg_cmd_unregister(cmd);
        --cmd;
    }
}
