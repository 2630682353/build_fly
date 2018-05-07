#include "timer.h"
#include <signal.h>

static LIST_HEAD(my_timer_list); 
static int timer_timeslot;

void timer_handler() {
	time_t cur = uptime();
	util_timer *p = NULL;
	util_timer *n = NULL;
	list_for_each_entry_safe(p, n, &my_timer_list, list) {
		if (cur >= p->expire) {
			p->cb_func(p->para);
			if (!p->loop) {
				list_del(&p->list);
				if (p->para)
					free(p->para);
				free(p);
			}
			else {
				p->expire = cur + p->interval;
			}
		}
	}
}

util_timer *add_timer(int (*cb_func)(),int delay,int loop, int interval, void *para, int type) {
	util_timer *t = malloc(sizeof(util_timer));
	t->cb_func = cb_func;
	t->expire = uptime() + delay;
	t->interval = interval;
	t->loop = loop;
	t->para = para;
	t->timer_type = type;
	list_add(&t->list, &my_timer_list);
	return t;
}

int del_timer(int type)
{
	util_timer *p = NULL;
	util_timer *n = NULL;
	list_for_each_entry_safe(p, n, &my_timer_list, list) {
		if (p->timer_type == type) {
			list_del(&p->list);
			if (p->para)
				free(p->para);
			free(p);
		}			
	}
	return 0;
}

int timer_list_init(int timeslot, void (*sig_handler)(int sig))
{
	timer_timeslot = timeslot;
	signal(SIGALRM, sig_handler);
	alarm(timer_timeslot);
	return 0;
}