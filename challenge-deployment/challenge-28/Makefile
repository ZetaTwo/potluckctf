CHALLENGE_ID = 28
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: Dockerfile flag.txt main.py
	docker build -t "$(LOCAL_IMAGE)" .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): Dockerfile main.py
	tar czvf $(DIST_FILE) Dockerfile main.py

clean:
	rm -f Dockerfile flag.txt main.py

download: Dockerfile flag.txt main.py

Dockerfile:
	gsutil cp $(DELIVERY_BUCKET)/Dockerfile .

flag.txt:
	gsutil cp $(DELIVERY_BUCKET)/flag.txt .

main.py:
	gsutil cp $(DELIVERY_BUCKET)/main.py .


.PHONY: build docker-build docker-push dist dist-push download
