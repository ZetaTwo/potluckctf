CHALLENGE_ID = 05
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge05-dist.tgz

docker-build: docker/
	docker build -t potluckctf:challenge-05 docker/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge05-dist.tgz: DIST-DEPENDENCIES # TODO: docker/ but edit "admin.properties" and "build.sh" for dist
	tar czvf challenge05-dist.tgz DIST-DEPENDENCIES

clean:
	rm -fr docker/ exp/ README.md

download: docker/ exp/ README.md

README.md:
	gsutil cp gs://potluckctf-challenge-5/challenge/README.md .

docker/:
	gsutil cp -r gs://potluckctf-challenge-5/challenge/docker/ .

exp/:
	gsutil cp -r gs://potluckctf-challenge-5/challenge/exp/ .

.PHONY: build docker-build docker-push download
