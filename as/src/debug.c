#include "debug.h"
#include "def.h"
#include <linux/string.h>
#include <linux/ctype.h>

#define DBG_BUFFER_MAXSIZE (768)
int32 debug_print(int8 *fmt,...)
{
    int8 buf[DBG_BUFFER_MAXSIZE];
    va_list va;
    bzero(buf, sizeof(buf));
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    printk("%s", buf);
    return strlen(buf);
}

int32 debug(const int32 level,
            const int8 *func,
            const int32 line,
            const char *file,
            int8 *fmt,...)
{
    int8 buf[DBG_BUFFER_MAXSIZE];
    int8 *p = NULL;
    int32 len = 0;
    va_list va;
    int8 *levelstr[] = {
            [DEBUG_LEVEL_INF]   = "INF",
            [DEBUG_LEVEL_WAR]   = "WAR",
            [DEBUG_LEVEL_ERR]   = "ERR",
            [DEBUG_LEVEL_PARAM] = "PARAM",
            [DEBUG_LEVEL_POS]   = "POS",
            [DEBUG_LEVEL_TRACE] = "TRACING"
        };
    
    ASSERT(DEBUG_LEVEL_VALID(level));
    bzero(buf, sizeof(buf));
    //snprintf(buf, sizeof(buf), "[%s]<%s@%u %s> ", levelstr[level], func, line, file);
    snprintf(buf, sizeof(buf), "[%s]<%s@%u> ", levelstr[level], func, line);
    len = strlen(buf);
    p = buf + len;
    va_start(va, fmt);
    vsnprintf(p, sizeof(buf)-len, fmt, va);
    va_end(va);
    len = strlen(buf);
    p = buf + len;
    snprintf(p, sizeof(buf)-len, "\r\n");
    printk("%s", buf);
    return strlen(buf);
}

void hexdump(int8 *p_title, 
             int8 *p_data,
             uint32 dlen,
             uint32 width)
{
	int32 i, j;
	uint32 c;
	int8 buf[256];
	int8 *p;
	int32 size;
	int32 n;

	ASSERT(width>=4 && width<=64);
	PRINTF("---------------- hexdump begin[%s],dlen[%u] ----------------\r\n", 
			p_title, dlen);
	for (i=0; i<dlen; i+=width)
	{
	    bzero(buf,sizeof(buf));
		p = buf;
		size = sizeof(buf);
		n = snprintf(p,size,"%p: ",p_data+i);
		ASSERT(n>=0);
		size -= n;
		p += n;
		for (j=i; j<dlen && j<(i+width); ++j)
		{
			c = p_data[j];
			c &= 0x000000ff;
			n = snprintf(p, size, "%02X", c);
			ASSERT(n>=0);
			size -= n;
			ASSERT(size>=0);
			p += n;
			if (0 == ((j+1)%2))
			{
				n = snprintf(p, size, " ");
				ASSERT(n>=0);
				size -= n;
				ASSERT(size>=0);
				p += n;
			}
		}
		PRINTF("%s", buf);

        PRINTF("    |    ");
        
	    bzero(buf,sizeof(buf));
        p = buf;
        size = sizeof(buf);
        for (j=i; j<dlen && j<(i+width); ++j)
		{
		    if (isprint(p_data[j]))
                sprintf(p,"%c",p_data[j]);
            else
                sprintf(p," ");
            ++p;
		}
		PRINTF("%s\r\n", buf);
	}
	PRINTF("---------------- hexdump end[%s],dlen[%u] ----------------\r\n", 
			p_title, dlen);
}
