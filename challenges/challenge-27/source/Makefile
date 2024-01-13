all:
	gcc -Wall -DDEBUG=1 -I./include -o main-debug src/*.c
	gcc -Wall -I./include -o main src/*.c

dist: program
	x86_64-linux-musl-gcc -Wall -I./include -o main_dist src/*.c -static
	x86_64-linux-musl-strip -s main_dist
	x86_64-linux-musl-gcc -DDEBUG=1 -Wall -I./include -o main_dist_debug src/*.c -static
	cp main_dist deploy/chall
	cp prog/kitchen.bin deploy/kitchen.bin
	cp prog/gordon.bin deploy/gordon.bin

program:
	python3 tools/asm.py prog/kitchen.asm prog/kitchen.bin
	@xxd prog/kitchen.bin
	python3 tools/asm.py prog/gordon.asm prog/gordon.bin
	@xxd prog/gordon.bin
	

clean:
	rm -rf main main_dist main_dist_debug prog/*.bin
