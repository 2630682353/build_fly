#include "list.h"
#include <stdlib.h>
#include <time.h>
typedef struct util_timer_st {
	time_t expire;
	int (*cb_func)();
	int loop;
	int interval;
	struct list_head list;
}util_timer;

extern void timer_handler();
extern util_timer *add_timer(int (*cb_func)(),int delay,int loop, int interval);
extern int del_timer(util_timer *u);
extern int timer_list_init(int timeslot, void (*sig_handler)(int sig));