CHALLENGE_ID = 07
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge07-dist.tgz

docker-build: deploy/
	docker build -t $(LOCAL_IMAGE) deploy/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge07-dist.tgz: public/
	tar -C public/ -czvf challenge07-dist.tgz bear_err.zip

clean:
	rm -fr deploy/ public/ solution/

download: deploy/ public/ solution/

deploy/:
	gsutil cp -r gs://potluckctf-challenge-7/deploy/ .

public/:
	gsutil cp -r gs://potluckctf-challenge-7/public/ .

solution/:
	gsutil cp -r gs://potluckctf-challenge-7/solution/ .

.PHONY: build docker-build docker-push download
