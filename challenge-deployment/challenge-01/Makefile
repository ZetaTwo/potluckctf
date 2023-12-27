CHALLENGE_ID = 01
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-1

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

docker-build: Dockerfile cake-of-paranoia-with-flag entrypoint.sh
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): rootfs.tar.zst
	tar czvf $(DIST_FILE) rootfs.tar.zst

clean:
	rm -rf Dockerfile cake-of-paranoia-with-flag entrypoint.sh rootfs.tar.zst README.md solve-scripts

download: Dockerfile cake-of-paranoia-with-flag entrypoint.sh rootfs.tar.zst README.md solve-scripts

Dockerfile:
	gcloud storage cp $(DELIVERY_BUCKET)/Dockerfile .

README.md:
	gcloud storage cp $(DELIVERY_BUCKET)/README.md .

cake-of-paranoia-with-flag:
	gcloud storage cp $(DELIVERY_BUCKET)/cake-of-paranoia-with-flag .

entrypoint.sh:
	gcloud storage cp $(DELIVERY_BUCKET)/entrypoint.sh .
	chmod +x entrypoint.sh

rootfs.tar.zst:
	gcloud storage cp $(DELIVERY_BUCKET)/rootfs.tar.zst .

solve-scripts:
	gcloud storage cp -r $(DELIVERY_BUCKET)/solve-scripts/ .

.PHONY: build docker-build docker-push dist dist-push download
