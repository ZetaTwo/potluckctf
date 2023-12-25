CHALLENGE_ID = 01
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-1

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

# TODO: Add PoW
docker-build: Dockerfile cake-of-paranoia-with-flag entrypoint.sh
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): rootfs.tar.zst
	tar czvf $(DIST_FILE) rootfs.tar.zst

clean:
	rm -f Dockerfile cake-of-paranoia-with-flag entrypoint.sh rootfs.tar.zst README.md solve-scripts

download: Dockerfile cake-of-paranoia-with-flag entrypoint.sh rootfs.tar.zst README.md solve-scripts

Dockerfile:
	gsutil cp $(DELIVERY_BUCKET)/Dockerfile .

README.md:
	gsutil cp $(DELIVERY_BUCKET)/README.md .

cake-of-paranoia-with-flag:
	gsutil cp $(DELIVERY_BUCKET)/cake-of-paranoia-with-flag .

entrypoint.sh:
	gsutil cp $(DELIVERY_BUCKET)/entrypoint.sh .

rootfs.tar.zst:
	gsutil cp $(DELIVERY_BUCKET)/rootfs.tar.zst .

solve-scripts:
	gsutil cp -r $(DELIVERY_BUCKET)/solve-scripts/ .

.PHONY: build docker-build docker-push dist dist-push download
