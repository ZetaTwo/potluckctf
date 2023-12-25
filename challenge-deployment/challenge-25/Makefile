CHALLENGE_ID = 25
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge25-dist.tgz

docker-build: DOCKER-DEPENDENCIES
	docker build -t "$(LOCAL_IMAGE)" .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge25-dist.tgz: downloads/user_bundle.tar.gz
	cp downloads/user_bundle.tar.gz challenge25-dist.tgz

clean:
	rm -rf downloads

download: downloads/Makefile downloads/deploy.cpio.gz downloads/deploy.flag.txt downloads/deploy_bundle.tar.gz downloads/hashcash.py downloads/init downloads/initramfs.cpio.gz downloads/kernel downloads/pow.py downloads/run.sh downloads/server.py downloads/task.service downloads/user.cpio.gz downloads/user.flag.txt downloads/user_bundle.tar.gz downloads/exploits/ downloads/src/

downloads:
	mkdir -p downloads

downloads/Makefile: downloads
	gsutil cp gs://potluckctf-challenge-25/Makefile downloads/

downloads/deploy.cpio.gz: downloads
	gsutil cp gs://potluckctf-challenge-25/deploy.cpio.gz downloads/

downloads/deploy.flag.txt: downloads
	gsutil cp gs://potluckctf-challenge-25/deploy.flag.txt downloads/

downloads/deploy_bundle.tar.gz: downloads
	gsutil cp gs://potluckctf-challenge-25/deploy_bundle.tar.gz downloads/

downloads/hashcash.py: downloads
	gsutil cp gs://potluckctf-challenge-25/hashcash.py downloads/

downloads/init: downloads
	gsutil cp gs://potluckctf-challenge-25/init downloads/

downloads/initramfs.cpio.gz: downloads
	gsutil cp gs://potluckctf-challenge-25/initramfs.cpio.gz downloads/

downloads/kernel: downloads
	gsutil cp gs://potluckctf-challenge-25/kernel downloads/

downloads/pow.py: downloads
	gsutil cp gs://potluckctf-challenge-25/pow.py downloads/

downloads/run.sh: downloads
	gsutil cp gs://potluckctf-challenge-25/run.sh downloads/

downloads/server.py: downloads
	gsutil cp gs://potluckctf-challenge-25/server.py downloads/

downloads/task.service: downloads
	gsutil cp gs://potluckctf-challenge-25/task.service downloads/

downloads/user.cpio.gz: downloads
	gsutil cp gs://potluckctf-challenge-25/user.cpio.gz downloads/

downloads/user.flag.txt: downloads
	gsutil cp gs://potluckctf-challenge-25/user.flag.txt downloads/

downloads/user_bundle.tar.gz: downloads
	gsutil cp gs://potluckctf-challenge-25/user_bundle.tar.gz downloads/

downloads/exploits/: downloads
	gsutil cp -r gs://potluckctf-challenge-25/exploits downloads/

downloads/src/: downloads
	gsutil cp -r gs://potluckctf-challenge-25/src downloads/

.PHONY: build docker-build docker-push download
