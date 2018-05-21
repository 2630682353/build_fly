PROJ = dpid
CC := @gcc
RM := @rm -f

CFLAGS := -Wall -g -DLINUX_APP -DDEBUG

INC_DIR := -I.
LIBS := -lpthread -lcurl -ljson-c -l:libz.a -lshare -lipc -luci

SOURCE := ${wildcard *.c}
OBJS := ${patsubst %.c, %.o, $(SOURCE)}

all: 
	$(CC) -c $(SOURCE) $(INC_DIR) $(CFLAGS)
	$(CC) -o $(PROJ) $(OBJS) $(LIBS)
.PHONY : all

clean:
	$(RM) *.o $(PROJ)
.PHONY:clean
