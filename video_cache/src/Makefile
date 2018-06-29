CFLAGS= -Wall -Os 

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)


video_cache: $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(OBJS) -o video_cache -lipc -lshare -lpthread
	

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o video_cache