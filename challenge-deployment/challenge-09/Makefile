CHALLENGE_ID = 09
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge09-dist.tgz

prebuilt_system: 0001-Store-the-open-file-descriptors-of-the-process-in-it.patch docker-compose.yml Dockerfile Dockerfile.build_system flag init potluck.config prebuilt_system/ prebuilt_system/bzImage prebuilt_system/initramfs.cpio.gz README.md
	echo echo "potluckctf{wh0ops_I_gu3ss_n0w_L1nus_1s_g01ng_t0_y31l_4t_m3}" > flag
	docker build --output=prebuilt_system --target=output -f Dockerfile.build_system .

docker-build: prebuilt_system run.sh
	docker build -t potluckctf:challenge-09 .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge09-dist.tgz: challenge-9-for-players.tar.gz
	mv challenge-9-for-players.tar.gz challenge09-dist.tgz

clean:
	rm -rf challenge-9-for-players.tar.gz challenge-9-for-zeta-two.tar.gz exploit/ 0001-Store-the-open-file-descriptors-of-the-process-in-it.patch docker-compose.yml Dockerfile Dockerfile.build_system flag init potluck.config prebuilt_system/ prebuilt_system/bzImage prebuilt_system/initramfs.cpio.gz README.md run.sh

download: challenge-9-for-players.tar.gz challenge-9-for-zeta-two.tar.gz

challenge-9-for-players.tar.gz:	
	gsutil cp gs://potluckctf-challenge-9/challenge-9-for-players.tar.gz .

challenge-9-for-zeta-two.tar.gz:	
	gsutil cp gs://potluckctf-challenge-9/challenge-9-for-zeta-two.tar.gz .

exploit: challenge-9-for-zeta-two.tar.gz
	tar xf challenge-9-for-zeta-two.tar.gz

0001-Store-the-open-file-descriptors-of-the-process-in-it.patch: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

docker-compose.yml: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

Dockerfile: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

Dockerfile.build_system: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

flag: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

init: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

potluck.config: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

prebuilt_system/: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

prebuilt_system/bzImage: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

prebuilt_system/initramfs.cpio.gz: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

README.md: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

run.sh: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

.PHONY: build docker-build docker-push download
