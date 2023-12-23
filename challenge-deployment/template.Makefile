CHALLENGE_ID = XX
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challengeXX-dist.tgz

docker-build: DOCKER-DEPENDENCIES
	docker build -t potluckctf:challenge-XX .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challengeXX-dist.tgz: DIST-DEPENDENCIES
	tar czvf challengeXX-dist.tgz DIST-DEPENDENCIES

clean:
	rm -f FILES

download: FILES

A-FILE:
	gsutil cp gs://potluckctf-challenge-X/A-FILE .


.PHONY: build docker-build docker-push download
