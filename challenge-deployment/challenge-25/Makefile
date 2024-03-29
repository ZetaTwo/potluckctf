CHALLENGE_ID = 25
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

docker-build: DOCKER-DEPENDENCIES
	docker build -t "$(LOCAL_IMAGE)" .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): downloads/user_bundle.tar.gz
	cp downloads/user_bundle.tar.gz $(DIST_FILE)

clean:
	rm -rf downloads	

download: downloads/Makefile downloads/deploy.cpio.gz downloads/deploy.flag.txt downloads/deploy_bundle.tar.gz downloads/hashcash.py downloads/init downloads/initramfs.cpio.gz downloads/kernel downloads/pow.py downloads/run.sh downloads/server.py downloads/task.service downloads/user.cpio.gz downloads/user.flag.txt downloads/user_bundle.tar.gz downloads/exploits downloads/src

downloads:
	mkdir -p downloads

downloads/Makefile: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/Makefile downloads/

downloads/deploy.cpio.gz: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/deploy.cpio.gz downloads/

downloads/deploy.flag.txt: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/deploy.flag.txt downloads/

downloads/deploy_bundle.tar.gz: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/deploy_bundle.tar.gz downloads/

downloads/hashcash.py: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/hashcash.py downloads/

downloads/init: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/init downloads/

downloads/initramfs.cpio.gz: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/initramfs.cpio.gz downloads/

downloads/kernel: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/kernel downloads/

downloads/pow.py: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/pow.py downloads/

downloads/run.sh: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/run.sh downloads/

downloads/server.py: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/server.py downloads/

downloads/task.service: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/task.service downloads/

downloads/user.cpio.gz: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/user.cpio.gz downloads/

downloads/user.flag.txt: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/user.flag.txt downloads/

downloads/user_bundle.tar.gz: downloads
	gcloud storage cp $(DELIVERY_BUCKET)/user_bundle.tar.gz downloads/

downloads/exploits: downloads
	gcloud storage cp -r $(DELIVERY_BUCKET)/exploits downloads/

downloads/src: downloads
	gcloud storage cp -r $(DELIVERY_BUCKET)/src downloads/

.PHONY: build docker-build docker-push dist dist-push download
