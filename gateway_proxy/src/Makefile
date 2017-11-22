CFLAGS= -Wall -Os 

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

gateway_proxy: gateway_proxy.o
	$(CC) $(LDFLAGS) $(CFLAGS) gateway_proxy.o -L. -lipc -lpthread -o gateway_proxy 

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o gateway_proxy