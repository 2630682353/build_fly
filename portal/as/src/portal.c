#include "portal.h"
#include "spinlock.h"
#include "log.h"
#include "debug.h"

static LIST_HEAD(s_list_portal_interface);
static spinlock_t s_spinlock_list_portal_interface;
static uint32 s_portal_interface_count = 0;

static inline int32 portal_interface_init(void)
{
    spinlock_init(&s_spinlock_list_portal_interface);
    s_portal_interface_count = 0;
    return 0;
}

static inline void portal_interface_destroy(void)
{
    portal_interface_t *interface;
    spinlock_lock(&s_spinlock_list_portal_interface);
    while (!list_empty(&s_list_portal_interface))
    {
        interface = list_first_entry(&s_list_portal_interface, portal_interface_t, list);
        list_del(&interface->list);
        free(interface);
    }
    s_portal_interface_count = 0;
    spinlock_unlock(&s_spinlock_list_portal_interface);
    spinlock_destroy(&s_spinlock_list_portal_interface);
}

int32 portal_interface_add(const int8 *ifname,
                           const int8 *url)
{
    portal_interface_t *interface = NULL;
    if (NULL == ifname ||strlen(ifname) <= 0 || strlen(ifname) >= IFNAME_SIZE
        || NULL == url || strlen(url) <= 0 || strlen(url) >= URL_SIZE)
    {
        DB_ERR("Invalid ifname(%s) or url(%s).", ifname, url);
        LOGGING_ERR("Apply portal '%s' to the interface '%s' failure with invalid parameter.", url, ifname);
        return -1;
    }
    spinlock_lock(&s_spinlock_list_portal_interface);
    list_for_each_entry(interface, &s_list_portal_interface, list)
    {
        if (0 == strcmp(interface->ifname, ifname))
            break;
    }
    if (NULL == interface || &s_list_portal_interface == &interface->list)
    {
        interface = (portal_interface_t *)malloc(sizeof(*interface));
        ASSERT(NULL != interface);
        strcpy(interface->ifname, ifname);
        strcpy(interface->url, url);
        atomic_set(&interface->refcnt, 1);
        list_add_tail(&interface->list, &s_list_portal_interface);
        ++s_portal_interface_count;
        spinlock_unlock(&s_spinlock_list_portal_interface);
        LOGGING_INFO("Apply portal '%s' to the interface '%s' successfully.", url, ifname);
        return 0;
    }
    else
    {
        spinlock_unlock(&s_spinlock_list_portal_interface);
        DB_WAR("Apply portal '%s' to the interface '%s' failure. "
            "Because the portal '%s' has been applied on the interface '%s'.", 
            url, ifname, interface->url, interface->ifname);
        LOGGING_WARNING("Apply portal '%s' to the interface '%s' failure. "
            "Because the portal '%s' has been applied on the interface '%s'.", 
            url, ifname, interface->url, interface->ifname);
        return 0;
    }
}

static inline void __portal_interface_delete(portal_interface_t *interface)
{
    if (atomic_dec_and_test(&interface->refcnt))
    {
        LOGGING_INFO("Delete portal '%s' from the interface '%s' successfully.", 
                interface->url, interface->ifname);
        list_del(&interface->list);
        free(interface);
        --s_portal_interface_count;
    }
}

void portal_interface_delete(const int8 *ifname)
{
    portal_interface_t *interface = NULL;
    if (NULL == ifname ||strlen(ifname) <= 0 || strlen(ifname) >= IFNAME_SIZE)
    {
        DB_ERR("Invalid ifname(%s).", ifname);
        LOGGING_ERR("Delete portal from the interface failure with invalid parameter. ifname[%s].", ifname);
    }
    spinlock_lock(&s_spinlock_list_portal_interface);
    list_for_each_entry(interface, &s_list_portal_interface, list)
    {
        if (0 == strcmp(interface->ifname, ifname))
            break;
    }
    if (NULL != interface && &s_list_portal_interface != &interface->list)
        __portal_interface_delete(interface);
    else
        LOGGING_WARNING("There is not applied portal to the interface '%s'.", ifname);
    spinlock_unlock(&s_spinlock_list_portal_interface);
}

portal_interface_t *portal_interface_get(const int8 *ifname)
{
    portal_interface_t *interface = NULL;
    if (NULL == ifname || strlen(ifname) <= 0)
        return NULL;
    spinlock_lock(&s_spinlock_list_portal_interface);
    list_for_each_entry(interface, &s_list_portal_interface, list)
    {
        if (0 == strcmp(interface->ifname, ifname))
            break;
    }
    if (NULL != interface && &s_list_portal_interface != &interface->list)
        atomic_inc(&interface->refcnt);
    else
        interface = NULL;
    spinlock_unlock(&s_spinlock_list_portal_interface);
    return interface;
}

void portal_interface_put(portal_interface_t *interface)
{
    if (NULL != interface)
    {
        spinlock_lock(&s_spinlock_list_portal_interface);
        __portal_interface_delete(interface);
        spinlock_unlock(&s_spinlock_list_portal_interface);
    }
}

BOOL portal_interface_exist(const int8 *ifname)
{
    portal_interface_t *interface = NULL;
    BOOL exist = FALSE;
    if (NULL == ifname || strlen(ifname) <= 0)
        return exist;
    spinlock_lock(&s_spinlock_list_portal_interface);
    list_for_each_entry(interface, &s_list_portal_interface, list)
    {
        if (0 == strcmp(interface->ifname, ifname))
        {
            exist = TRUE;
            break;
        }
    }
    spinlock_unlock(&s_spinlock_list_portal_interface);
    return exist;
}


static LIST_HEAD(s_list_portal_vlan);
static spinlock_t s_spinlock_list_portal_vlan;
static uint32 s_portal_vlan_count = 0;

static inline int32 portal_vlan_init(void)
{
    spinlock_init(&s_spinlock_list_portal_vlan);
    s_portal_vlan_count = 0;
    return 0;
}

static inline void portal_vlan_destroy(void)
{
    portal_vlan_t *vlan;
    spinlock_lock(&s_spinlock_list_portal_vlan);
    while (!list_empty(&s_list_portal_vlan))
    {
        vlan = list_first_entry(&s_list_portal_vlan, portal_vlan_t, list);
        list_del(&vlan->list);
        free(vlan);
    }
    s_portal_vlan_count = 0;
    spinlock_unlock(&s_spinlock_list_portal_vlan);
    spinlock_destroy(&s_spinlock_list_portal_vlan);
}

int32 portal_vlan_add(const uint16 vlan_id,
                      const int8 *url)
{
    portal_vlan_t *vlan = NULL;
    if (vlan_id <= 0 || NULL == url || strlen(url) <= 0 || strlen(url) >= URL_SIZE)
    {
        DB_ERR("Invalid vlan_id(%u) or url(%s).", vlan_id, url);
        LOGGING_ERR("Apply portal '%s' to the vlan '%u' failure with invalid parameter.", url, vlan_id);
        return -1;
    }
    spinlock_lock(&s_spinlock_list_portal_vlan);
    list_for_each_entry(vlan, &s_list_portal_vlan, list)
    {
        if (vlan_id == vlan->vlan_id)
            break;
    }
    if (NULL == vlan || &s_list_portal_vlan == &vlan->list)
    {
        vlan = (portal_vlan_t *)malloc(sizeof(*vlan));
        ASSERT(NULL != vlan);
        vlan->vlan_id = vlan_id;
        strcpy(vlan->url, url);
        atomic_set(&vlan->refcnt, 1);
        list_add_tail(&vlan->list, &s_list_portal_vlan);
        ++s_portal_vlan_count;
        spinlock_unlock(&s_spinlock_list_portal_vlan);
        LOGGING_INFO("Apply portal '%s' to the vlan '%u' successfully.", url, vlan_id);
        return 0;
    }
    else
    {
        spinlock_unlock(&s_spinlock_list_portal_vlan);
        DB_WAR("Apply portal '%s' to the vlan '%u' failure, "
            "Because the portal '%s' has been applied on the vlan '%u'.", 
            url, vlan_id, vlan->url, vlan->vlan_id);
        LOGGING_WARNING("Apply portal '%s' to the vlan '%u' failure, "
            "Because the portal '%s' has been applied on the vlan '%u'.", 
            url, vlan_id, vlan->url, vlan->vlan_id);
        return 0;
    }
}

static inline void __portal_vlan_delete(portal_vlan_t *vlan)
{
    if (atomic_dec_and_test(&vlan->refcnt))
    {
        LOGGING_INFO("Delete portal '%s' from the vlan '%u' successfully.", vlan->url, vlan->vlan_id);
        list_del(&vlan->list);
        free(vlan);
        --s_portal_vlan_count;
    }
}

void portal_vlan_delete(const uint16 vlan_id)
{
    portal_vlan_t *vlan = NULL;
    if (vlan_id <= 0)
    {
        DB_ERR("Invalid vlan_id(%u).", vlan_id);
        LOGGING_ERR("Delete portal from the vlan failure with invalid parameter. vlan_id[%u].", vlan_id);
        return ;
    }
    spinlock_lock(&s_spinlock_list_portal_vlan);
    list_for_each_entry(vlan, &s_list_portal_vlan, list)
    {
        if (vlan_id == vlan->vlan_id)
            break;
    }
    if (NULL != vlan && &s_list_portal_vlan != &vlan->list)
        __portal_vlan_delete(vlan);
    else
        LOGGING_WARNING("There is not applied portal to the vlan '%u'.", vlan_id);
    spinlock_unlock(&s_spinlock_list_portal_vlan);
}

portal_vlan_t *portal_vlan_get(const uint16 vlan_id)
{
    portal_vlan_t *vlan = NULL;
    if (vlan_id <= 0)
        return NULL;
    spinlock_lock(&s_spinlock_list_portal_vlan);
    list_for_each_entry(vlan, &s_list_portal_vlan, list)
    {
        if (vlan_id == vlan->vlan_id)
            break;
    }
    if (NULL != vlan && &s_list_portal_vlan != &vlan->list)
        atomic_inc(&vlan->refcnt);
    else
        vlan = NULL;
    spinlock_unlock(&s_spinlock_list_portal_vlan);
    return vlan;
}

void portal_vlan_put(portal_vlan_t *vlan)
{
    if (NULL != vlan)
    {
        spinlock_lock(&s_spinlock_list_portal_vlan);
        __portal_vlan_delete(vlan);
        spinlock_unlock(&s_spinlock_list_portal_vlan);
    }
}

BOOL portal_vlan_exist(const uint16 vlan_id)
{
    portal_vlan_t *vlan = NULL;
    BOOL exist = FALSE;
    if (vlan_id <= 0)
        return exist;
    spinlock_lock(&s_spinlock_list_portal_vlan);
    list_for_each_entry(vlan, &s_list_portal_vlan, list)
    {
        if (vlan_id == vlan->vlan_id)
        {
            exist = TRUE;
            break;
        }
    }
    spinlock_unlock(&s_spinlock_list_portal_vlan);
    return exist;
}

int32 portal_init(void)
{
    if (0 != portal_interface_init())
    {
        DB_ERR("portal_interface_init() call fail.");
        return -1;
    }
    if (0 != portal_vlan_init())
    {
        DB_ERR("portal_vlan_init() call fail.");
        portal_interface_destroy();
        return -1;
    }
    return 0;
}

void portal_destroy(void)
{
    portal_interface_destroy();
    portal_vlan_destroy();
}


#define PROC_PORTAL             "portal"
#define PROC_PORTAL_INTERFACE   "interface"
#define PROC_PORTAL_VLAN        "vlan"
static struct proc_dir_entry *sp_proc_portal = NULL;
static struct proc_dir_entry *sp_proc_portal_interface = NULL;
static struct proc_dir_entry *sp_proc_portal_vlan = NULL;

static ssize_t portal_interface_proc_read(struct file *file, 
                                          int8 __user *buf, 
                                          size_t size, 
                                          loff_t *ppos)
{
    int8 tmp[512];
    int32 len;
    int32 copyed = 0;
    struct list_head *head = (struct list_head *)file->private_data;
    portal_interface_t *interface;
    if (unlikely(&s_list_portal_interface == head))
    {
        len = sprintf(tmp, "portal apply to interface count:%u\n", s_portal_interface_count);
        len += sprintf(tmp+len, "%-16s%-16s\n", 
                    "ifname", "url");
        if (len > *ppos)
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    while (likely(copyed < size))
    {
        if (unlikely(head->next == &s_list_portal_interface))
            break;
        interface = list_first_entry(head, portal_interface_t, list);
        len = sprintf(tmp, "%-16s%-16s\n", 
                interface->ifname, interface->url);
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &interface->list;
        file->private_data = (void *)&interface->list;
    }
    *ppos += copyed;
    return copyed;
}

static int32 portal_interface_proc_open(struct inode *inode, 
                                        struct file *file)
{
    file->private_data = (void *)&s_list_portal_interface;
    spinlock_lock(&s_spinlock_list_portal_interface);
    return 0;
}

static int32 portal_interface_proc_close(struct inode *inode, 
                                         struct file *file)
{
    spinlock_unlock(&s_spinlock_list_portal_interface);
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_portal_interface_proc_fileops = {
    .owner      = THIS_MODULE,
    .read       = portal_interface_proc_read,
    .open       = portal_interface_proc_open,
    .release    = portal_interface_proc_close
};

static int32 portal_interface_proc_init(struct proc_dir_entry *parent)
{
    struct proc_dir_entry *entry = proc_create(PROC_PORTAL_INTERFACE, 0, parent, &s_portal_interface_proc_fileops);
    if (NULL == entry)
    {
        DB_ERR("proc_create(%s) fail!!", PROC_PORTAL_INTERFACE);
        return -1;
    }
    sp_proc_portal_interface = entry;
    return 0;
}

static void portal_interface_proc_destroy(struct proc_dir_entry *parent)
{
    if (NULL != sp_proc_portal_interface)
    {
        remove_proc_entry(PROC_PORTAL_INTERFACE, parent);
        sp_proc_portal_interface = NULL;
    }
}

static ssize_t portal_vlan_proc_read(struct file *file, 
                                     int8 __user *buf, 
                                     size_t size, 
                                     loff_t *ppos)
{
    int8 tmp[512];
    int32 len;
    int32 copyed = 0;
    struct list_head *head = (struct list_head *)file->private_data;
    portal_vlan_t *vlan;
    if (unlikely(&s_list_portal_vlan == head))
    {
        len = sprintf(tmp, "portal apply to vlan count:%u\n", s_portal_vlan_count);
        len += sprintf(tmp+len, "%-16s%-16s\n", 
                    "vlan_id", "url");
        if (len > *ppos)
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    while (likely(copyed < size))
    {
        if (unlikely(head->next == &s_list_portal_vlan))
            break;
        vlan = list_first_entry(head, portal_vlan_t, list);
        len = sprintf(tmp, "%-16u%-16s\n", 
                vlan->vlan_id, vlan->url);
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &vlan->list;
        file->private_data = (void *)&vlan->list;
    }
    *ppos += copyed;
    return copyed;
}

static int32 portal_vlan_proc_open(struct inode *inode, 
                                   struct file *file)
{
    file->private_data = (void *)&s_list_portal_vlan;
    spinlock_lock(&s_spinlock_list_portal_vlan);
    return 0;
}

static int32 portal_vlan_proc_close(struct inode *inode, 
                                    struct file *file)
{
    spinlock_unlock(&s_spinlock_list_portal_vlan);
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_portal_vlan_proc_fileops = {
    .owner      = THIS_MODULE,
    .read       = portal_vlan_proc_read,
    .open       = portal_vlan_proc_open,
    .release    = portal_vlan_proc_close
};

static int32 portal_vlan_proc_init(struct proc_dir_entry *parent)
{
    struct proc_dir_entry *entry = proc_create(PROC_PORTAL_VLAN, 0, parent, &s_portal_vlan_proc_fileops);
    if (NULL == entry)
    {
        DB_ERR("proc_create(%s) fail!!", PROC_PORTAL_VLAN);
        return -1;
    }
    sp_proc_portal_vlan = entry;
    return 0;
}

static void portal_vlan_proc_destroy(struct proc_dir_entry *parent)
{
    if (NULL != sp_proc_portal_vlan)
    {
        remove_proc_entry(PROC_PORTAL_VLAN, parent);
        sp_proc_portal_vlan = NULL;
    }
}

int32 portal_proc_init(struct proc_dir_entry *parent)
{
    struct proc_dir_entry *entry = proc_mkdir(PROC_PORTAL, parent);
    if (NULL == entry)
    {
        DB_ERR("proc_mkdir(%s) fail!!", PROC_PORTAL);
        return -1;
    }
    sp_proc_portal = entry;
    if (0 != portal_interface_proc_init(sp_proc_portal))
    {
        DB_ERR("portal_interface_proc_init() call fail!!");
        remove_proc_entry(PROC_PORTAL, parent);
        sp_proc_portal = NULL;
        return -1;
    }
    if (0 != portal_vlan_proc_init(sp_proc_portal))
    {
        DB_ERR("portal_vlan_proc_init() call fail!!");
        portal_interface_proc_destroy(sp_proc_portal);
        remove_proc_entry(PROC_PORTAL, parent);
        sp_proc_portal = NULL;
        return -1;
    }
    return 0;
}

void portal_proc_destroy(struct proc_dir_entry *parent)
{
    if (NULL != sp_proc_portal)
    {
        portal_interface_proc_destroy(sp_proc_portal);
        portal_vlan_proc_destroy(sp_proc_portal);
        remove_proc_entry(PROC_PORTAL, parent);
        sp_proc_portal = NULL;
    }
}