all: pass_store

pass_store: main.o pass_store.o
	gcc main.o pass_store.o -lcrypto -o pass_store

main.o: main.c
	gcc -g -Wall -c main.c -o main.o

pass_store.o: pass_store.c
	gcc -g -Wall -c pass_store.c -o pass_store.o

clean:
	rm -rf pass_store *.o
