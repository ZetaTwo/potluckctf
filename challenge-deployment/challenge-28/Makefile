CHALLENGE_ID = 28
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge28-dist.tgz

docker-build: Dockerfile flag.txt main.py
	docker build -t "$(LOCAL_IMAGE)" .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge28-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge28-dist.tgz DIST-DEPENDENCIES

clean:
	rm -f Dockerfile flag.txt main.py

download: Dockerfile flag.txt main.py

Dockerfile:
	gsutil cp gs://potluckctf-challenge-28/Dockerfile .

flag.txt:
	gsutil cp gs://potluckctf-challenge-28/flag.txt .

main.py:
	gsutil cp gs://potluckctf-challenge-28/main.py .


.PHONY: build docker-build docker-push download
