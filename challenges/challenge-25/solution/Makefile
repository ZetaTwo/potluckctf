ALL = powpow a

.PHONY: all
all: $(ALL)

$(ALL): %: %.c
	musl-gcc -Wall -Wextra -Werror -std=c11 -static -Os -o $@ $^
