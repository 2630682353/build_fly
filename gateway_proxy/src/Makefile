CFLAGS= -Wall -Os 

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

gateway_proxy: $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(OBJS) -o gateway_proxy -lipc -lshare -lcurl -lpthread

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o gateway_proxy