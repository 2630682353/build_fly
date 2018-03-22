#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#ifdef  __cplusplus
extern "C" {
#endif


#include <linux/spinlock.h>
#ifndef spinlock_t
#define spinlock_t                          spinlock_t
#endif
#ifndef spinlock_init
#define spinlock_init(lock)                 spin_lock_init((lock))
#endif
#ifndef spinlock_destroy
#define spinlock_destroy(lock)              do{}while(0)
#endif
#ifndef spinlock_lock
#define spinlock_lock(lock)                 spin_lock((lock))
#endif
#ifndef spinlock_unlock
#define spinlock_unlock(lock)               spin_unlock((lock))
#endif
#ifndef spinlock_lock_irq
#define spinlock_lock_irq(lock)             spin_lock_irq((lock))
#endif
#ifndef spinlock_unlock_irq
#define spinlock_unlock_irq(lock)           spin_unlock_irq((lock))
#endif
#ifndef spinlock_lock_bh
#define spinlock_lock_bh(lock)              spin_lock_bh((lock))
#endif
#ifndef spinlock_unlock_bh
#define spinlock_unlock_bh(lock)            spin_unlock_bh((lock))
#endif
#ifndef spinlock_lock_irqsave
#define spinlock_lock_irqsave(lock,flag)    spin_lock_irqsave((lock),(flag))
#endif
#ifndef spinlock_unlock_irqrestore
#define spinlock_unlock_irqrestore(lock,flag)    spin_unlock_irqrestore((lock),(flag))
#endif


#ifdef  __cplusplus
}
#endif

#endif /*__SPINLOCK_H__*/
