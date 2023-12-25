CHALLENGE_ID = 05
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-5

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: docker/
	docker build -t $(LOCAL_IMAGE) docker/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): DIST-DEPENDENCIES # TODO: docker/ but edit "admin.properties" and "build.sh" for dist
	tar czvf $(DIST_FILE) DIST-DEPENDENCIES

clean:
	rm -fr docker/ exp/ README.md

download: docker/ exp/ README.md

README.md:
	gsutil cp $(DELIVERY_BUCKET)/challenge/README.md .

docker/:
	gsutil cp -r $(DELIVERY_BUCKET)/challenge/docker/ .

exp/:
	gsutil cp -r $(DELIVERY_BUCKET)/challenge/exp/ .

.PHONY: build docker-build docker-push dist dist-push download
