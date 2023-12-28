CHALLENGE_ID = 09
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-9

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

prebuilt_system: 0001-Store-the-open-file-descriptors-of-the-process-in-it.patch docker-compose.yml Dockerfile Dockerfile.build_system flag init potluck.config prebuilt_system/ prebuilt_system/bzImage prebuilt_system/initramfs.cpio.gz README.md debugging-goodies.patch
	echo "potluckctf{wh0ops_I_gu3ss_n0w_L1nus_1s_g01ng_t0_y31l_4t_m3}" > flag
	docker build --output=prebuilt_system --target=output -f Dockerfile.build_system .

docker-build: prebuilt_system run.sh
	docker build -t potluckctf:challenge-09 .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): challenge-9-for-players.tar.gz
	cp challenge-9-for-players.tar.gz $(DIST_FILE)

clean:
	rm -rf challenge-9-for-players.tar.gz challenge-9-for-zeta-two.tar.gz exploit/ 0001-Store-the-open-file-descriptors-of-the-process-in-it.patch docker-compose.yml Dockerfile Dockerfile.build_system flag init potluck.config prebuilt_system/ prebuilt_system/bzImage prebuilt_system/initramfs.cpio.gz README.md run.sh debugging-goodies.patch

download: challenge-9-for-players.tar.gz challenge-9-for-zeta-two.tar.gz

challenge-9-for-players.tar.gz:	
	gcloud storage cp $(DELIVERY_BUCKET)/challenge-9-for-players.tar.gz .

challenge-9-for-zeta-two.tar.gz:	
	gcloud storage cp $(DELIVERY_BUCKET)/challenge-9-for-zeta-two.tar.gz .

exploit: challenge-9-for-zeta-two.tar.gz
	tar xf challenge-9-for-zeta-two.tar.gz

0001-Store-the-open-file-descriptors-of-the-process-in-it.patch: challenge-9-for-players.tar.gz
	tar xf challenge-9-for-players.tar.gz

debugging-goodies.patch: challenge-9-for-players.tar.gz
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
