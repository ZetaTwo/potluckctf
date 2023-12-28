CHALLENGE_ID = 14
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

$(DIST_FILE): release.7z
	tar czvf $(DIST_FILE) release.7z

clean:
	rm -f release.7z

download: release.7z

release.7z:
	gcloud storage cp $(DELIVERY_BUCKET)/release.7z .

.PHONY: build docker-build docker-push dist dist-push download
