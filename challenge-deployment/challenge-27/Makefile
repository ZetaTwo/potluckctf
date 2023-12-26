CHALLENGE_ID = 27
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

docker-build: shells-kitchen
	docker build -t $(LOCAL_IMAGE) shells-kitchen/deploy

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): shells-kitchen/
	cp shells-kitchen/dist.tar.gz $(DIST_FILE)

clean:
	rm -fr shells-kitchen/

download: shells-kitchen/

shells-kitchen:
	gcloud storage cp -r $(DELIVERY_BUCKET)/shells-kitchen .


.PHONY: build docker-build docker-push dist dist-push download
