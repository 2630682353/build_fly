#ifndef __CONFIG_H__
#define __CONFIG_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"

void config_authenticated_timeout(const int8 *mac);
int32 config_init(void);
void config_final(void);

#ifdef  __cplusplus
}
#endif

#endif /*__CONFIG_H__*/
