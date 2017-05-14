CFLAGS = -ggdb
SRCS = semtech_aes.c hexdump.c

OBJS=$(SRCS:.c=.o)

all: loracrypt loraskeys


loracrypt: $(OBJS) loracrypt.o
	$(CC) -o loracrypt loracrypt.o $(OBJS)

loraskeys: $(OBJS) loraskeys.o
	$(CC) -o loraskeys loraskeys.o $(OBJS)

