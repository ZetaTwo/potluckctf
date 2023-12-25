CHALLENGE_ID = 26
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge26-dist.tgz

docker-build: DOCKER-DEPENDENCIES
	docker build -t "$(LOCAL_IMAGE)" .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge26-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge26-dist.tgz DIST-DEPENDENCIES

clean:
	rm -fr downloads/

download: downloads/build

downloads:
	mkdir -p downloads

downloads/build: downloads
	gsutil cp -r gs://potluckctf-challenge-26/build downloads/

.PHONY: build docker-build docker-push download
