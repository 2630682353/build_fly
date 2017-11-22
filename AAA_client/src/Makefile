CFLAGS= -Wall -Os 

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

all:radius_client radacct
radacct: radacct.o
	$(CC) $(LDFLAGS) $(CFLAGS) radacct.o libfreeradius-client.a -o radacct 

radius_client: radius_client.o log.o
	$(CC) $(LDFLAGS) $(CFLAGS) radius_client.o log.o libfreeradius-client.a -L. -lipc -lpthread -o radius_client 

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o radius_client radacct