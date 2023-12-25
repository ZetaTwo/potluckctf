CHALLENGE_ID = 06
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-6

build: docker-build docker-push

docker-build: release_build/ Dockerfile
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

clean:
	rm -fr OTHER_LICENSES README.md release_build/ release_source/

download: OTHER_LICENSES README.md release_build/ release_source/

OTHER_LICENSES:
	gcloud storage cp $(DELIVERY_BUCKET)/OTHER_LICENSES .

README.md:
	gcloud storage cp $(DELIVERY_BUCKET)/README.md .

release_build/:
	gcloud storage cp -r $(DELIVERY_BUCKET)/release_build/ .

release_source/:
	gcloud storage cp -r $(DELIVERY_BUCKET)/release_source/ .

.PHONY: build docker-build docker-push dist dist-push download
