CC=gcc
CFLAGS=-I.
DEPS = 
OBJTST = psock_test.o
OBJFFS = xpt_ffs_setup.o

all: psock_test xpt_ffs_setup

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

psock_test: $(OBJTST)
	$(CC) -o $@ $^ $(CFLAGS)

xpt_ffs_setup: $(OBJFFS)
	$(CC) -o $@ $^ $(CFLAGS) -lconfig -lusbgx

clean : 
	-rm $(OBJFFS) $(OBJTST)
	-rm psock_test xpt_ffs_setup
