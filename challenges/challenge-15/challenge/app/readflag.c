// this isnt vulnerable, this just enforces setuid because you can't do that with shell scripts
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
	setuid(0);
	FILE *file = fopen("/app/actual-flag", "r");
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	while ((read = getline(&line, &len, file)) != -1) {
			printf("%s", line);
	} 
	
	return 0;
}
