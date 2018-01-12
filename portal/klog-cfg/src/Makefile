PROJ = klog-cfg
CC := @gcc
RM := @rm -f

CFLAGS := -Wall -g

INC_DIR := -I.
LIBS := 

SOURCE := ${wildcard *.c}
OBJS := ${patsubst %.c, %.o, $(SOURCE)}

all: 
	$(CC) -c $(SOURCE) $(INC_DIR) $(CFLAGS)
	$(CC) -o $(PROJ) $(OBJS) $(LIBS)
.PHONY : all

clean:
	$(RM) *.o $(PROJ)
.PHONY:clean
