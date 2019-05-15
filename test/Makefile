CC=gcc
CFLAGS=-I.
DEPS = 
OBJ = psock_test.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

psock_test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean : 
	-rm $(OBJ)
	-rm psock_test
