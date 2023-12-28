CHALLENGE_ID = 15
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

#dist: $(DIST_FILE)

#dist-push: dist
#	gcloud storage cp $(DIST_FILE) gs://potluckctf

#dist-url:
#	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

docker-build: downloads/app downloads/Dockerfile downloads/actual-flag
	docker build -t "$(LOCAL_IMAGE)" "downloads"

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

#$(DIST_FILE): downloads/app downloads/Dockerfile
#	tar -C downloads -czvf $(DIST_FILE) app Dockerfile

clean:
	rm -fr chal-DO-NOT-SEND-TO-PLAYERS.tar downloads chal-v1.3.tar

download: chal-v1.3.tar

downloads:
	mkdir -p downloads

downloads/app: downloads chal-v1.3.tar
	tar -C downloads -xf chal-v1.3.tar

downloads/.gitignore: downloads chal-v1.3.tar
	tar -C downloads -xf chal-v1.3.tar

downloads/actual-flag: downloads chal-v1.3.tar
	tar -C downloads -xf chal-v1.3.tar

downloads/Dockerfile: downloads chal-v1.3.tar
	tar -C downloads -xf chal-v1.3.tar

chal-v1.3.tar:
	gcloud storage cp $(DELIVERY_BUCKET)/chal-v1.3.tar .


.PHONY: build docker-build docker-push dist dist-push download
