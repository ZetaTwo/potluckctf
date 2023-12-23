CHALLENGE_ID = 18
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge18-dist.tgz

docker-build: secret/
	docker build -t $(LOCAL_IMAGE) secret/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge18-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge18-dist.tgz DIST-DEPENDENCIES TODO

clean:
	rm -f distributables/ secret/

download: distributables/ secret/

distributables/:
	gsutil cp -r gs://potluckctf-challenge-18/distributables .

secret/:
	gsutil cp -r gs://potluckctf-challenge-18/secret .

.PHONY: build docker-build docker-push download
