CHALLENGE_ID = 00
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build

docker-build: Dockerfile cowsay.sh
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

clean:

.PHONY: docker-build docker-push
