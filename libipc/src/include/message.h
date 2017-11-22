#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"

#define DEFINE_CMD(module, type ,code) (((module)<<24)|((type)<<16)|(code))
#define MODULE_GET(cmd) ((cmd)>>24)
#define MODULE_TYPE_GET(cmd) (((cmd)>>16) & 0x00FF)

enum module_type {
	USER_MODULE = 0,
	KERNEL_MODULE
};

enum module_mid {
	MODULE_GATEWAY = 1,
	MODULE_DPI,
	MODULE_WS,
	MODULE_RADIUS,
	MODULE_GATEWAY_KERNEL,
	MODULE_DPI_KERNEL,
	MODULE_WS_KERNEL,
	MODULE_RADIUS_KERNEL,
	MODULE_MAX			//must be end
};

enum {
	GATEWAY_QUERY = DEFINE_CMD(MODULE_GATEWAY, USER_MODULE, 1),
	GATEWAY_TEST2,
	GATEWAY_TEST3
	};
	
enum {
	WS_TEST1 = DEFINE_CMD(MODULE_WS, USER_MODULE, 1),
	WS_TEST2
	};

enum {
	RADIUS_AUTH = DEFINE_CMD(MODULE_RADIUS, USER_MODULE, 1),
	};

enum {
	DPI_TEST1 = DEFINE_CMD(MODULE_DPI, USER_MODULE, 1),
	DPI_TEST2,
	DPI_TEST3
	};


enum {
	GATEWAY_KERNEL_TEST1 = DEFINE_CMD(MODULE_GATEWAY_KERNEL, KERNEL_MODULE, 1),
	GATEWAY_KERNEL_TEST2,
	GATEWAY_KERNEL_TEST3
	};

enum {
	DPI_KERNEL_TEST1 = DEFINE_CMD(MODULE_DPI_KERNEL, KERNEL_MODULE, 1),
	DPI_KERNEL_TEST2,
	DPI_KERNEL_TEST3
	};

enum {
	WS_KERNEL_TEST1 = DEFINE_CMD(MODULE_WS_KERNEL, KERNEL_MODULE, 1),
	};

enum {
	RADIUS_KERNEL_TEST1 = DEFINE_CMD(MODULE_RADIUS_KERNEL, KERNEL_MODULE, 1),
	};


#define NETLINK_EVENT     30
#define NETLINK_UMSG     31

enum error_code {
	ERR_CODE_NONECMD = 1,
	ERR_CODE_INPUT,
	ERR_CODE_FILE,
	ERR_CODE_MALLOC,
	ERR_CODE_AUTHFAIL,
	ERR_CODE_QUERYNONE
};

typedef int32 (*msg_cmd_handle_cb)(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen);

typedef struct msg_st{
    int16    ver;        /*版本号,目前为0x01*/
 	int16    flag;       /*0:表示请求报文;1:表示应答报文*/
    int32   cmd;        /*操作命令字,详见msg_cmd_e的定义*/
    int16   smid;       /*源模块ID*/
    int16   dmid;       /*目的模块ID*/
    int16   sn;         /*序列号,请求报文和应答报文中的序列号必须相同*/
    int16   result;     /*操作结果,请求报文中恒为0,应答报文中返回0或错误码*/
    int32   dlen;       /*数据长度,不包含协议头*/
    int8    data[0];    /*数据*/
}msg_t;

/*参数:模块id，线程数，域套接字接收地址，域套接字发送地址*/
extern int32 msg_init(const int16 module_id, const int32 thd_num, char *rcv_path, char *snd_path); 
extern int32 msg_cmd_register(const int32 cmd, msg_cmd_handle_cb cb);
extern int32 msg_cmd_unregister(const int32 cmd);

extern int32 msg_dst_module_register_unix(const int32 mid, char *path);
extern int32 msg_dst_module_register_netlink(const int32 mid);

extern int32 msg_dst_module_unregister(const int32 mid);
extern void msg_final(void);
extern int32 msg_send_syn(int32 cmd, void *sbuf, int32 slen, void **rbuf, int32 *rlen);
extern int32 free_rcv_buf(void *rcv_buf);

#ifdef  __cplusplus
}
#endif

#endif /*__MESSAGE_H__*/

