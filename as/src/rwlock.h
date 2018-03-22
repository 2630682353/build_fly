#ifndef __RWLOCK_H__
#define __RWLOCK_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/rwlock.h>
#ifndef rwlock_t
#define rwlock_t                                rwlock_t
#endif
#ifndef rwlock_init
#define rwlock_init(lock)                       rwlock_init((lock))
#endif
#ifndef rwlock_destroy
#define rwlock_destroy(lock)                    do{}while(0)
#endif

#ifndef rwlock_rdlock
#define rwlock_rdlock(lock)                     read_lock((lock))
#endif
#ifndef rwlock_rdunlock
#define rwlock_rdunlock(lock)                   read_unlock((lock))
#endif
#ifndef rwlock_rdlock_irq
#define rwlock_rdlock_irq(lock)                 read_lock_irq((lock))
#endif
#ifndef rwlock_rdunlock_irq
#define rwlock_rdunlock_irq(lock)               read_unlock_irq((lock))
#endif
#ifndef rwlock_rdlock_bh
#define rwlock_rdlock_bh(lock)                  read_lock_bh((lock))
#endif
#ifndef rwlock_rdunlock_bh
#define rwlock_rdunlock_bh(lock)                read_unlock_bh((lock))
#endif
#ifndef rwlock_rdlock_irqsave
#define rwlock_rdlock_irqsave(lock,flag)        read_lock_irqsave((lock),(flag))
#endif
#ifndef rwlock_rdunlock_irqrestore
#define rwlock_rdunlock_irqrestore(lock,flag)   read_unlock_irqrestore((lock),(flag))
#endif

#ifndef rwlock_wrlock
#define rwlock_wrlock(lock)                     write_lock((lock))
#endif
#ifndef rwlock_wrunlock
#define rwlock_wrunlock(lock)                   write_unlock((lock))
#endif
#ifndef rwlock_wrlock_irq
#define rwlock_wrlock_irq(lock)                 write_lock_irq((lock))
#endif
#ifndef rwlock_wrunlock_irq
#define rwlock_wrunlock_irq(lock)               write_unlock_irq((lock))
#endif
#ifndef rwlock_wrlock_bh
#define rwlock_wrlock_bh(lock)                  write_lock_bh((lock))
#endif
#ifndef rwlock_wrunlock_bh
#define rwlock_wrunlock_bh(lock)                write_unlock_bh((lock))
#endif
#ifndef rwlock_wrlock_irqsave
#define rwlock_wrlock_irqsave(lock,flag)        write_lock_irqsave((lock),(flag))
#endif
#ifndef rwlock_wrunlock_irqrestore
#define rwlock_wrunlock_irqrestore(lock,flag)   write_unlock_irqrestore((lock),(flag))
#endif

#ifdef  __cplusplus
}
#endif

#endif /*__RWLOCK_H__*/

