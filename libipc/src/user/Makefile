
CFLAGS=-Wall -I../include -Os -fPIC
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
MYOBJS= memory_pool.o  sock.o thread_pool.o message.o debug.o

target: $(MYOBJS)  
	$(CC) -o libipc.so -shared $(CFLAGS) $(MYOBJS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o *.so libipc.so
