BUSYBOX_VERSION = 1.36.1
SHELL := /bin/bash
BUSYBOX_DIR = busybox-$(BUSYBOX_VERSION)
BUSYBOX_URL = https://busybox.net/downloads/busybox-$(BUSYBOX_VERSION).tar.bz2

.PHONY: all
all: user_bundle.tar.gz deploy_bundle.tar.gz

FORCE:

busybox.tar.bz2:
	wget "$(BUSYBOX_URL)" -O $@

$(BUSYBOX_DIR)/Makefile: busybox.tar.bz2
	rm -rf $(BUSYBOX_DIR)
	tar -xmf $<

$(BUSYBOX_DIR)/.config: $(BUSYBOX_DIR)/Makefile
	$(MAKE) -C $(BUSYBOX_DIR) clean
	$(MAKE) -C $(BUSYBOX_DIR) defconfig
	sed -e 's/.*CONFIG_FEATURE_SUID.*/CONFIG_FEATURE_SUID=n/' -i $(BUSYBOX_DIR)/.config

$(BUSYBOX_DIR)/busybox: $(BUSYBOX_DIR)/.config
	$(MAKE) -C $(BUSYBOX_DIR)

$(BUSYBOX_DIR)/_install/bin/busybox: $(BUSYBOX_DIR)/busybox
	$(MAKE) -C $(BUSYBOX_DIR) install

src/service src/dummy_init: src_make
	@:

.INTERMEDIATE: src_make
src_make: FORCE
	$(MAKE) -C src

initramfs/bin/busybox: $(BUSYBOX_DIR)/_install/bin/busybox init src/service src/dummy_init
	rm -rf initramfs
	cp -r $(BUSYBOX_DIR)/_install/ initramfs
	cd initramfs && mkdir -p usr/lib lib64 proc tmp
	cp /usr/lib/libc.so.6 /usr/lib/libm.so.6 /usr/lib/libresolv.so.2 initramfs/usr/lib/
	cp /usr/lib64/ld-linux-x86-64.so.2 initramfs/lib64/ld-linux-x86-64.so.2
	cp src/service src/dummy_init initramfs/
	cp init initramfs/init

%.cpio.gz: %.flag.txt initramfs/bin/busybox
	cp -f $< initramfs/flag.txt
	cd initramfs && find . | cpio -R +0:+0 -o -H newc | gzip -9 > ../$@

user_bundle.tar.gz: kernel run.sh user.cpio.gz
	ln -sf user.cpio.gz initramfs.cpio.gz
	tar -czf $@ $^ initramfs.cpio.gz src/{Makefile,service.c,dummy_init.c}

deploy_bundle.tar.gz: kernel run.sh deploy.cpio.gz
	ln -sf deploy.cpio.gz initramfs.cpio.gz
	tar -czf $@ $^ initramfs.cpio.gz server.py hashcash.py task.service
