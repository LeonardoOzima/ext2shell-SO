CC = gcc
CFLAGS = -Wall -g -fno-stack-protector

PROG = ext2shell
OBJ = ext2shell.o ext2shell-aux.o

all: $(PROG)

$(PROG): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

ext2shell.o: ext2shell.c ext2shell-aux.h ext2shell-consts.h
	$(CC) $(CFLAGS) -c ext2shell.c

ext2shell-aux.o: ext2shell-aux.c ext2shell-aux.h ext2shell-consts.h
	$(CC) $(CFLAGS) -c ext2shell-aux.c

clean:
	rm -f $(PROG) $(OBJ)