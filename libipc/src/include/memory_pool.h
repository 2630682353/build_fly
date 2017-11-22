#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H
#include "list.h"
// 内存块结构体  
typedef struct mempool_st mempool_t;
typedef struct  memunit_st memunit_info_t;

// 内存池结构体  
typedef struct mempool_st
{  
	int unitsize;			  // 内存单元大小，即unit的大小	
	int initnum;			 // 初始内存单元的数目  
	int grownum;		   // 每次新增内存单元的数目  
	int totalnum;			 // 内存单元总数	
	int idlenum;  
	pthread_mutex_t mutex;
	struct list_head idlelist;		 // 空闲内存单元链表头   
}mempool_t; 
// 内存单元信息  
typedef struct  memunit_st
{  
    struct list_head idlelist;
	mempool_t *mempool;
	char data[0];
}memunit_info_t; 

extern void* mem_alloc(mempool_t* p);
extern int mem_free(void* p);
//unitsize是内存块大小,initnum是初始内存块个数，grownum是内存块不够一次增长的个数
extern mempool_t* memory_pool_init(int unitsize, int initnum, int grownum);
extern int memory_pool_destroy(mempool_t* p);

#endif



