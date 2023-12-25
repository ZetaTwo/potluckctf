CHALLENGE_ID = 19
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

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
	gcloud storage cp gs://potluckctf-challenge-19/README.md .

app:
	gcloud storage cp -r gs://potluckctf-challenge-19/app/ .

handout:
	gcloud storage cp -r gs://potluckctf-challenge-19/handout/ .

solve:
	gcloud storage cp -r gs://potluckctf-challenge-19/solve/ .

.PHONY: build docker-build docker-push dist dist-push download
