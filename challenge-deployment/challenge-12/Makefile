CHALLENGE_ID = 12
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge12-dist.tgz

oci-image.tar: oci-image.tar.zst
	zstd -d oci-image.tar.zst

docker-build: oci-image.tar
	docker import oci-image.tar "potluckctf:challenge-12"

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge12-dist.tgz:
	gsutil cp gs://potluckctf-challenge-12/challenge12-dist.tgz .

clean:
	rm -fr challenge12-dist.tgz oci-image.tar.zst oci-image.tar src-806f208.zip swgcc710-cross-6b-9916.tar.gz

download: challenge12-dist.tgz oci-image.tar.zst src-806f208.zip swgcc710-cross-6b-9916.tar.gz

oci-image.tar.zst:
	gsutil cp gs://potluckctf-challenge-12/oci-image.tar.zst .

src-806f208.zip:
	gsutil cp gs://potluckctf-challenge-12/src-806f208.zip .

swgcc710-cross-6b-9916.tar.gz:
	gsutil cp gs://potluckctf-challenge-12/swgcc710-cross-6b-9916.tar.gz .

.PHONY: build docker-build docker-push download
