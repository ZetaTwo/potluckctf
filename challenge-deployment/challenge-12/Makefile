CHALLENGE_ID = 12
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

oci-image.tar: oci-image.tar.zst
	zstd -d oci-image.tar.zst

docker-build: oci-image.tar
	docker import oci-image.tar "potluckctf:challenge-12"

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE):
	gcloud storage cp $(DELIVERY_BUCKET)/challenge12-dist.tgz .

clean:
	rm -fr challenge12-dist.tgz oci-image.tar.zst oci-image.tar src-806f208.zip swgcc710-cross-6b-9916.tar.gz

download: challenge12-dist.tgz oci-image.tar.zst src-806f208.zip swgcc710-cross-6b-9916.tar.gz

oci-image.tar.zst:
	gcloud storage cp $(DELIVERY_BUCKET)/oci-image.tar.zst .

src-806f208.zip:
	gcloud storage cp $(DELIVERY_BUCKET)/src-806f208.zip .

swgcc710-cross-6b-9916.tar.gz:
	gcloud storage cp $(DELIVERY_BUCKET)/swgcc710-cross-6b-9916.tar.gz .

.PHONY: build docker-build docker-push dist dist-push download
