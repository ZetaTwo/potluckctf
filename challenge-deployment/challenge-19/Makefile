CHALLENGE_ID = 19
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: app
	docker build -t "$(LOCAL_IMAGE)" app

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): handout
	tar -C handout -czvf $(DIST_FILE) ezrop libc.so.6

clean:
	rm -fr README.md app handout solve

download: README.md app handout solve 

README.md:
	gsutil cp gs://potluckctf-challenge-19/README.md .

app:
	gsutil cp -r gs://potluckctf-challenge-19/app/ .

handout:
	gsutil cp -r gs://potluckctf-challenge-19/handout/ .

solve:
	gsutil cp -r gs://potluckctf-challenge-19/solve/ .

.PHONY: build docker-build docker-push dist dist-push download
