#ifndef __RWLOCK_H__
#define __RWLOCK_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/rwlock.h>
#ifndef rwlock_t
#define rwlock_t                rwlock_t
#endif
#ifndef rwlock_init
#define rwlock_init(lock)       rwlock_init((lock))
#endif
#ifndef rwlock_destroy
#define rwlock_destroy(lock)    do{}while(0)
#endif
#ifndef rwlock_rdlock
#define rwlock_rdlock(lock)     read_lock_irq((lock))
#endif
#ifndef rwlock_tryrdlock
#define rwlock_tryrdlock(lock)  read_trylock((lock))    /*0:fail; !=0:success*/
#endif
#ifndef rwlock_rdunlock
#define rwlock_rdunlock(lock)   read_unlock_irq((lock))
#endif
#ifndef rwlock_wrlock
#define rwlock_wrlock(lock)     write_lock_irq((lock))
#endif
#ifndef rwlock_trywrlock
#define rwlock_trywrlock(lock)  write_trylock((lock))   /*0:fail; !=0:success*/
#endif
#ifndef rwlock_wrunlock
#define rwlock_wrunlock(lock)   write_unlock_irq((lock))
#endif

#ifdef  __cplusplus
}
#endif

#endif /*__RWLOCK_H__*/

