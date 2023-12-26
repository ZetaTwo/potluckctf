CHALLENGE_ID = 15
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

docker-build: downloads/app downloads/Dockerfile
	docker build -t "$(LOCAL_IMAGE)" "downloads"

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): DIST-DEPENDENCIES
	tar czvf $(DIST_FILE) DIST-DEPENDENCIES

clean:
	rm -fr chal-DO-NOT-SEND-TO-PLAYERS.tar downloads

download: chal-DO-NOT-SEND-TO-PLAYERS.tar

downloads:
	mkdir -p downloads

downloads/app: downloads chal-DO-NOT-SEND-TO-PLAYERS.tar
	tar -C downloads -xf chal-DO-NOT-SEND-TO-PLAYERS.tar

downloads/.gitignore: downloads chal-DO-NOT-SEND-TO-PLAYERS.tar
	tar -C downloads -xf chal-DO-NOT-SEND-TO-PLAYERS.tar

downloads/actual-flag: downloads chal-DO-NOT-SEND-TO-PLAYERS.tar
	tar -C downloads -xf chal-DO-NOT-SEND-TO-PLAYERS.tar

downloads/Dockerfile: downloads chal-DO-NOT-SEND-TO-PLAYERS.tar
	tar -C downloads -xf chal-DO-NOT-SEND-TO-PLAYERS.tar

chal-DO-NOT-SEND-TO-PLAYERS.tar:
	gcloud storage cp $(DELIVERY_BUCKET)/chal-DO-NOT-SEND-TO-PLAYERS.tar .


.PHONY: build docker-build docker-push dist dist-push download
