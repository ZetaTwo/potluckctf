CC=arm-none-eabi-gcc

FLAG1=potluck{duMp1n6_th3_b0o7l0ad3r_4_fuN_&_pr0f1t}
FLAG2=potluck{y_i5_s3curb007_s0_h4rD}
CFLAGS=-mthumb -mcpu=cortex-m0 -ffunction-sections -fno-unwind-tables -fno-exceptions

BOOTLOADER_OBJS=\
	exception_handlers.o \
	stack.o \
	stdlib.o \
	nvic.o \
	uart.o \
	printf.o \
	strtol.o \
	sha256.o \
	reset.o \
	nvmc.o \
	app_checksum.o \
	bootloader.o

APP_OBJS=\
	exception_handlers.o \
	stdlib.o \
	stack.o \
	nvic.o \
	uart.o \
	strtol.c \
	app.o

FLAGLOADER_OBJS=\
	stack.o \
	nvmc.o \
	bootloader_embedded.o \
	flagloader.o

.PHONY: all
all: flagloader.hex bootloader.hex app.elf fwupd.py

bootloader.hex: bootloader.elf
	arm-none-eabi-objcopy -O ihex $< $@

bootloader.elf: $(BOOTLOADER_OBJS) bootloader.ld
	$(CC) -o $@ -flto -fno-fat-lto-objects $(CFLAGS) -Wl,--gc-sections -nostartfiles -Tbootloader.ld -Wl,-z,max-page-size=0x100 $(BOOTLOADER_OBJS)

bootloader.bin: bootloader.elf
	arm-none-eabi-objcopy -O binary $< $@

bootloader_embedded.o: bootloader.bin
	arm-none-eabi-objcopy -I binary -O elf32-littlearm --rename-section .data=.embed $< $@

bootloader.o: bootloader.c
	$(CC) -c -o $@ $(CFLAGS) -DFLAG1="${FLAG1}" $<

flagloader.o: flagloader.c
	$(CC) -c -o $@ $(CFLAGS) -DFLAG2="${FLAG2}" $<

flagloader.elf: $(FLAGLOADER_OBJS) flagloader.ld
	$(CC) -o $@ $(CFLAGS) -nostartfiles -Tflagloader.ld $(FLAGLOADER_OBJS)

flagloader.hex: flagloader.elf
	arm-none-eabi-objcopy -O ihex $< $@

app.elf: $(APP_OBJS) app.ld
	$(CC) -o $@ $(CFLAGS) -flto -fno-fat-lto-objects -Wl,--gc-sections -nostartfiles -Wl,-z,max-page-size=0x100 -Tapp.ld $(APP_OBJS)

app.fw: app.elf
	python3 generate_flash_fw.py

fwupd.py: app.fw fwupd_tail.py
	echo "fw=\"\"\"" > $@
	cat $< >> $@
	echo "\"\"\"" >> $@
	cat fwupd_tail.py >> $@

app_checksum.c: app.elf build_app_hash.py
	echo "#include <unistd.h>" > $@
	echo "char app_hash[0x20] = {" >> $@
	python3 build_app_hash.py | xxd -r -p - | xxd -i >> $@
	echo "};" >> $@

printf.o: printf/printf.c
	$(CC) -c -o $@ $(CFLAGS) \
		-DPRINTF_DISABLE_SUPPORT_FLOAT \
		-DPRINTF_DISABLE_SUPPORT_EXPONENTIAL \
		$^

.PHONY: clean
clean:
	rm -f *.hex *.elf *.bin *.o app_checksum.c

.PHONY: run
run: flagloader.hex
	# FIXME: disable mon
	qemu-system-arm -M microbit -device loader,file=flagloader.hex -nographic -serial mon:stdio

debug: flagloader.hex
	qemu-system-arm -s -S -M microbit -device loader,file=flagloader.hex -nographic -serial mon:stdio
