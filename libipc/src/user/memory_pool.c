
#include <stdlib.h>
#include <stdio.h>
#include "list.h"
#include "memory_pool.h"


int new_mem(mempool_t *p, int unitnum)
{
	int unitsize = p->unitsize;
	int i;
	memunit_info_t *ptr = NULL;
	for(i = 0; i < unitnum; i++) {
		while ((ptr=(memunit_info_t *)malloc(sizeof(memunit_info_t)+unitsize)) == NULL);
		list_add(&ptr->idlelist, &p->idlelist);
		ptr->mempool = p;
		p->idlenum++;
		p->totalnum++;
	}
	return 0;
}

void *mem_alloc(mempool_t *p)
{
	pthread_mutex_lock(&p->mutex);
	if (p->idlenum == 0) {
		new_mem(p, p->grownum);
	}
	memunit_info_t *first = list_first_entry(&p->idlelist, memunit_info_t, idlelist);
	list_del(&first->idlelist);
	p->idlenum--;
	pthread_mutex_unlock(&p->mutex);
	return first->data;
}

int mem_free(void *p)
{
	if (p == NULL)
		return -1;
	memunit_info_t *own = container_of(p, memunit_info_t, data);
	mempool_t *pool = own->mempool;
	pthread_mutex_lock(&pool->mutex);
	pool->idlenum++;
	list_add(&own->idlelist, &pool->idlelist);
	if ((pool->totalnum > pool->initnum) && (pool->idlenum > pool->grownum)) {
		int i;
		for(i = 0; i < pool->grownum; i++)
		{
			memunit_info_t *first = list_first_entry(&pool->idlelist, memunit_info_t, idlelist);
			list_del(&first->idlelist);
			pool->idlenum--;
			pool->totalnum--;
			free(first);
			printf("free\n");
		}
	}
	pthread_mutex_unlock(&pool->mutex);
	return 0;
}

mempool_t* memory_pool_init(int unitsize, int initnum, int grownum)
{
	mempool_t *p = NULL;
	p = malloc(sizeof(mempool_t));
	if (p==NULL)
		return p;
	p->unitsize = unitsize;
	p->initnum = initnum;
	p->grownum = grownum;
	p->totalnum = 0;
	p->idlenum = 0;
	pthread_mutex_init(&p->mutex, NULL);
	INIT_LIST_HEAD(&p->idlelist);
	new_mem(p, initnum);
	return p;
}

int memory_pool_destroy(mempool_t *p)
{
	memunit_info_t *unit;
	memunit_info_t *next_unit;
	list_for_each_entry_safe(unit, next_unit, &p->idlelist, idlelist) {
		list_del(&unit->idlelist);
		free(unit);
		printf("free\n");
	}
	free(p);
	p = NULL;
	return 0;
}

/*
int main()
{
	mempool_t *p = memory_pool_init(1024, 10, 10);
	char *test[20] = {0};
	int i;
	for(i = 0;i < 20; i++){
		test[i] = mem_alloc(p);
		printf("%d   %p  totalnum: %d idlenum: %d\n",i, test[i], p->totalnum, p->idlenum);
		sleep(1);
	}
	for(i = 0;i < 10; i++){
		mem_free(test[i]);
	}
	for(i = 0;i < 10; i++){
		test[i] = mem_alloc(p);
		printf("%d   %p  totalnum: %d idlenum: %d\n",i, test[i], p->totalnum, p->idlenum);
		sleep(1);
	}
	for(i = 0;i < 20; i++){
		mem_free(test[i]);
	}
	printf("totalnum: %d idlenum: %d\n",p->totalnum, p->idlenum);
	memory_pool_destroy(p);

}
*/