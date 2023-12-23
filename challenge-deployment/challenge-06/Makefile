CHALLENGE_ID = 06
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge06-dist.tgz

docker-build: release_build/ Dockerfile
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge06-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge06-dist.tgz DIST-DEPENDENCIES TODO

clean:
	rm -fr OTHER_LICENSES README.md release_build/ release_source/

download: OTHER_LICENSES README.md release_build/ release_source/

OTHER_LICENSES:
	gsutil cp gs://potluckctf-challenge-6/OTHER_LICENSES .

README.md:
	gsutil cp gs://potluckctf-challenge-6/README.md .

release_build/:
	gsutil cp -r gs://potluckctf-challenge-6/release_build/ .

release_source/:
	gsutil cp -r gs://potluckctf-challenge-6/release_source/ .

.PHONY: build docker-build docker-push download
