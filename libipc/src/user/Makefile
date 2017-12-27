
CFLAGS=-Wall -I../include -Os -fPIC
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)


target: $(OBJS)  
	$(CC) -o libipc.so -shared $(CFLAGS) $(OBJS) -lpthread
	$(STRIP) libipc.so

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o *.so libipc.so
