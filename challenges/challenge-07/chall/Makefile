CC = gcc
CFLAGS = -Wall -Werror -Wno-deprecated-declarations -g
OBJS = simple.o base64.o signature.o

all: simple

simple: $(OBJS) 
	$(CC) $(CFLAGS) -pthread -o $@ $(OBJS) -lcrypto -lssl

clean:
	rm *.o simple

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@