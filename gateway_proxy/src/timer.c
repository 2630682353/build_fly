#include "timer.h"
#include <signal.h>

static LIST_HEAD(my_timer_list); 
static int timer_timeslot;

void timer_handler() {
	time_t cur = time(NULL);
	util_timer *p = NULL;
	util_timer *n = NULL;
	list_for_each_entry_safe(p, n, &my_timer_list, list) {
		if (cur >= p->expire) {
			p->cb_func();
			if (!p->loop) {
				list_del(&p->list);
				free(p);
			}
			else {
				p->expire = cur + p->interval;
			}
		}
	}
	alarm(timer_timeslot);
}

util_timer *add_timer(void (*cb_func)(),int delay,int loop, int interval) {
	util_timer *t = malloc(sizeof(util_timer));
	t->cb_func = cb_func;
	t->expire = time(NULL) + delay;
	t->interval = interval;
	t->loop = loop;
	list_add(&t->list, &my_timer_list);
	return t;
}

int del_timer(util_timer *u)
{
	list_del(&u->list);
	free(u);
	return 0;
}

int timer_list_init(int timeslot, void (*sig_handler)(int sig))
{
	timer_timeslot = timeslot;
	signal(SIGALRM, sig_handler);
	alarm(timer_timeslot);
}