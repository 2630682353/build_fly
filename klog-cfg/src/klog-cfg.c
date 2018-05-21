#include "klog.h"
#include <sys/ioctl.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static inline int32 do_ioctl(const int32 cmd,
                             void *arg)
{
    int32 fd;
    int32 ret;
    fd = open("/dev/klog", O_RDWR);
    if (fd < 0)
        return -1;
    if (NULL == arg)
        ret = ioctl(fd, cmd);
    else
        ret = ioctl(fd, cmd, arg);
    close(fd);
    return ret;
}

static int32 level_main(int32 argc, 
                        int8 **argv)
{
    int32 level;
    int32 ret;
    int8 *levelstr[] = {[L_CRIT]    = "CRITICAL",
                        [L_ERR]     = "ERROR",
                        [L_WARNING] = "WARNING",
                        [L_NOTICE]  = "NOTICE",
                        [L_INFO]    = "INFORMATION",
                        [L_DEBUG]   = "DEBUG"};
    --argc;
    ++argv;
    if (0 == argc)
    {
        level = 0;
        ret = do_ioctl(LOGCMD_GET_LEVEL, (void *)&level);
        if (0 != ret)
        {
            printf("Query klog level fail. errno[%d].\n", errno);
            return ret;
        }
        if (!LOG_LEVEL_VALID(level))
            printf("Unknown klog level[%d].\n", level);
        else
            printf("Current klog level is %d(%s)\n", level, levelstr[level]);
        return ret;
    }
    level = atoi(*argv);
    if (!LOG_LEVEL_VALID(level))
    {
        printf("Unknown klog level[%d].\n", level);
        return -1;
    }
    ret = do_ioctl(LOGCMD_CHANGE_LEVEL, (void *)&level);
    if (0 != ret)
        printf("Set klog level fail. level[%d], errno[%d].\n", level, errno);
    return ret;
}

static int32 logon_main(int32 argc,
                        int8 **argv)
{
    int32 ret;
    --argc;
    ++argv;
    ret = do_ioctl(LOGCMD_LOG_ON, NULL);
    if (0 != ret)
        printf("Open the klog switch fail.\n");
    return ret;
}

static int32 logoff_main(int32 argc,
                         int8 **argv)
{
    int32 ret;
    --argc;
    ++argv;
    ret = do_ioctl(LOGCMD_LOG_OFF, NULL);
    if (0 != ret)
        printf("Close the klog switch fail.\n");
    return ret;
}

static int32 status_main(int32 argc,
                         int8 **argv)
{
    int32 ret;
    int32 status;
    --argc;
    ++argv;
    ret = do_ioctl(LOGCMD_LOG_STATUS, (void *)&status);
    if (0 != ret)
        printf("Get current klog's status fail.\n");
    else
        printf("Current klog's status is %s.\n", status ? "ON" : "OFF");
    return ret;
}

static inline void usage(void)
{
    printf("klog config command usage:\n");
    printf("  level [number]: Set/Query the klog storage level. number[0~5].\n"
           "      0: critical;\n"
           "      1: error;\n"
           "      2: warning;\n"
           "      3: notice;\n"
           "      4: information;\n"
           "      5: debug.\n");
    printf("  logon: Open the klog switch.\n");
    printf("  logoff: Close the klog switch.\n");
    printf("  status: The status of current klog.\n");
    printf("  help/?: Display this help and exit.\n");
}

static int32 help_main(int32 argc, 
                       int8 **argv)
{
    usage();
    return 0;
}

static struct {
    const int8 *name;
    int32 (*func)(int32 argc, int8 **argv);
} s_operate_funcs[] = {
    {"level",   level_main},
    {"logon",   logon_main},
    {"logoff",  logoff_main},
    {"status",  status_main},
    {"help",    help_main},
    {"?",       help_main}
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif
static int32 do_cmd(int32 argc, 
                    int8 **argv)
{
    int32 i;
    if (argc <=0 || NULL == argv)
    {
        printf("Invalid command.\n");
        usage();
        return -1;
    }
    for (i = 0; i < ARRAY_SIZE(s_operate_funcs); ++i)
    {
        if (0 == strcmp(argv[0], s_operate_funcs[i].name))
            return s_operate_funcs[i].func(argc, argv);
    }
    printf("Undefined command \"%s\"!\n", argv[0]);
    usage();
    return -1;
}

int32 main (int32 argc, int8 **argv)
{
    if (argc < 2)
    {
        usage();
        return 0;
    }
    else
        return do_cmd(--argc, ++argv);
}
