CHALLENGE_ID = 18
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

docker-build: secret
	docker build -t $(LOCAL_IMAGE) secret/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): distributables
	tar -C distributables -czvf $(DIST_FILE) final.py

clean:
	rm -rf distributables/ secret/

download: distributables/ secret/

distributables:
	gcloud storage cp -r $(DELIVERY_BUCKET)/distributables .

secret:
	gcloud storage cp -r $(DELIVERY_BUCKET)/secret .

.PHONY: build docker-build docker-push dist dist-push download
