CHALLENGE_ID = 27
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge27-dist.tgz

docker-build: shells-kitchen/
	docker build -t $(LOCAL_IMAGE) shells-kitchen/deploy

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge27-dist.tgz: shells-kitchen/
	tar czvf challenge27-dist.tgz DIST-DEPENDENCIES TODO

clean:
	rm -fr shells-kitchen/

download: shells-kitchen/

shells-kitchen/:
	gsutil cp -r gs://potluckctf-challenge-27/shells-kitchen .


.PHONY: build docker-build docker-push download
