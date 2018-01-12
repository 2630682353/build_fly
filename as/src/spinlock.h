#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#ifdef  __cplusplus
extern "C" {
#endif


#include <linux/spinlock.h>
#ifndef spinlock_t
#define spinlock_t spinlock_t
#endif
#ifndef spinlock_init
#define spinlock_init(lock) spin_lock_init(lock)
#endif
#ifndef spinlock_destroy
#define spinlock_destroy(lock) do{}while(0)
#endif
#ifndef spinlock_lock
#define spinlock_lock(lock) spin_lock(lock)
#endif
#ifndef spinlock_unlock
#define spinlock_unlock(lock) spin_unlock(lock)
#endif


#ifdef  __cplusplus
}
#endif

#endif /*__SPINLOCK_H__*/
