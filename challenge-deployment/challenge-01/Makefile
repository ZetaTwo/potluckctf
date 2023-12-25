CHALLENGE_ID = 01
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push dist

dist: challenge01-dist.tgz

# TODO: Add PoW
docker-build: Dockerfile cake-of-paranoia-with-flag entrypoint.sh
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge01-dist.tgz: rootfs.tar.zst
	tar czvf challenge01-dist.tgz rootfs.tar.zst

clean:
	rm -f Dockerfile cake-of-paranoia-with-flag entrypoint.sh rootfs.tar.zst README.md solve-scripts

download: Dockerfile cake-of-paranoia-with-flag entrypoint.sh rootfs.tar.zst README.md solve-scripts

Dockerfile:
	gsutil cp gs://potluckctf-challenge-1/Dockerfile .

README.md:
	gsutil cp gs://potluckctf-challenge-1/README.md .

cake-of-paranoia-with-flag:
	gsutil cp gs://potluckctf-challenge-1/cake-of-paranoia-with-flag .

entrypoint.sh:
	gsutil cp gs://potluckctf-challenge-1/entrypoint.sh .

rootfs.tar.zst:
	gsutil cp gs://potluckctf-challenge-1/rootfs.tar.zst .

solve-scripts:
	gsutil cp -r gs://potluckctf-challenge-1/solve-scripts/ .

.PHONY: build docker-build docker-push download
