CHALLENGE_ID = 29
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge29-dist.tgz

docker-build: Dockerfile server.py requirements.txt
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge29-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge29-dist.tgz DIST-DEPENDENCIES

clean:
	rm -f challenge29-dist.tar.gz service.tar.gz docker-compose.yml Dockerfile server.py requirements.txt

download: challenge29-dist.tar.gz service.tar.gz

challenge29-dist.tar.gz:
	gsutil cp gs://potluckctf-challenge-29/challenge29-dist.tar.gz .

service.tar.gz:
	gsutil cp gs://potluckctf-challenge-29/service.tar.gz .

docker-compose.yml: service.tar.gz
	tar xf service.tar.gz

Dockerfile: service.tar.gz
	tar xf service.tar.gz

server.py: service.tar.gz
	tar xf service.tar.gz

requirements.txt: service.tar.gz
	tar xf service.tar.gz

.PHONY: build docker-build docker-push download
