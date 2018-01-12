#ifndef __MUTEX_H__
#define __MUTEX_H__

#ifdef  __cplusplus
extern "C" {
#endif


#include <linux/mutex.h>
#ifndef mutex_t
#define mutex_t                 struct mutex
#endif
#ifndef mutex_init
#define mutex_init(lock)        mutex_init((lock))
#endif
#ifndef mutex_destroy
#define mutex_destroy(lock)     mutex_destroy((lock))
#endif
#ifndef mutex_lock
#define mutex_lock(lock)        mutex_lock((lock))
#endif
#ifndef mutex_trylock
#define mutex_trylock(lock)     mutex_trylock((lock))   /*0:fail; !=0:success*/
#endif
#ifndef mutex_unlock
#define mutex_unlock(lock)      mutex_unlock((lock))
#endif


#ifdef  __cplusplus
}
#endif

#endif /*__MUTEX_H__*/
