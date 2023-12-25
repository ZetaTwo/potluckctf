CHALLENGE_ID = 18
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: secret/
	docker build -t $(LOCAL_IMAGE) secret/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): DIST-DEPENDENCIES
	tar czvf $(DIST_FILE) DIST-DEPENDENCIES TODO

clean:
	rm -rf distributables/ secret/

download: distributables/ secret/

distributables/:
	gsutil cp -r $(DELIVERY_BUCKET)/distributables .

secret/:
	gsutil cp -r $(DELIVERY_BUCKET)/secret .

.PHONY: build docker-build docker-push dist dist-push download
