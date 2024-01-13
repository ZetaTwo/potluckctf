#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>


#define MAX_ALLOC_COUNT 0x80
#define MAX_MALLOC_SIZE 0x600

void *alloc_arr[MAX_ALLOC_COUNT];
unsigned int alloc_count = 0;

int speak(char *ptr) {
	int len = strlen(ptr);
	return write(STDOUT_FILENO, ptr, len);
}

void *prep(void) {
	unsigned long long addr = 0;
	
	// Disable libc buffering
	setvbuf(stdin, 0LL, 2, 0LL);
  	setvbuf(stdout, 0LL, 2, 0LL);
  	setvbuf(stderr, 0LL, 2, 0LL);
	
	// Create buffer needed for win check and flag buffer
	getrandom(&addr, sizeof(addr), GRND_RANDOM); 
	addr = addr&0xffffffff000;
	
	void *win = mmap((void*)addr, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE , 0, 0);
	
	// Set the win condition to be a dummy value
	*(unsigned long long *)win = 0xf00dbeefcafe1337;
	
	// Read flag to win buf+0x100
	int flag_fd = open("flag.txt", O_RDONLY);

	if ( read(flag_fd, win+0x100, 200) == -1 ) {
		speak("Error reading flag. Plz contact chal author\n\x00");
		exit(1);
	};
	close(flag_fd);
	
	// Copy win pointer to heap
	void *win_in_heap = malloc(0x18);
	*(unsigned long long*)win_in_heap = (unsigned long long*)win;

	// Sandbox binary to prevent one_gadgets
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	
	return win;
}

void dinner(void *win) {
	char flag[201];
	speak("Checking for win condition...\n\x00");
	if (*(unsigned long long *)win == 0x37C3C7F) {
		speak(win+0x100);
		exit(0);
	}
	else {
		speak("Try harder\n\x00");
	}
}


void do_malloc(void) {
	unsigned long malloc_size = 0;
	unsigned long write_offset = 0;

	if (alloc_count >= MAX_ALLOC_COUNT) {
		speak("Reached max allocations.\n\x00");
		exit(1);
	}

	speak("Allocation size: \x00");
	if (scanf("%lu", &malloc_size)  <= 0) {
		exit(1);
	}

	if (malloc_size > MAX_MALLOC_SIZE) {
		speak("We do not have the capacity for that many guests...\n\x00");
		exit(1);
	}
	
	void *buf = malloc(malloc_size);
	if (!buf) {
		speak("Failed to malloc. Assuming fatal error.\n\x00");
		exit(1);
	}

	alloc_arr[alloc_count++] = buf;
	
	speak("Write offset: \x00");
	if (scanf("%lu", &write_offset) <= 0) {
		exit(1);
	}
	if (write_offset >= malloc_size) {
		speak("Why would you do something as silly as that?\n\x00");
		exit(1);
	}


	speak("Data for buffer: \x00");
	read(STDIN_FILENO, buf+write_offset, malloc_size-write_offset);
}

void do_free(void) {
	unsigned int free_idx = 0;
	speak("Free idx: \x00");
	
	if (scanf("%u", &free_idx)  <= 0) {
		exit(1);
	}
	if (free_idx >= alloc_count) {
		speak("You cannot free something that is yet to be....\n\x00");
		exit(1);
	}
	
	free(alloc_arr[free_idx]);
}

void menu(void) {
	speak("1. make allocation\n\x00");
	speak("2. do free\n\x00");
	speak("3. go eat dinner!\n\x00");
	speak("> \x00");
}

int main(void) {
	void *win = prep();
	unsigned int option = 0;

	while (1) {
		menu();
		if (scanf("%u", &option)  <= 0 ) {
			exit(1);
		}
		switch(option) {
			case 1:
				do_malloc();
				break;
			case 2:
				do_free();
				break;
			case 3:
				dinner(win);
				break;
			default:
				break;
		}
	}
}
