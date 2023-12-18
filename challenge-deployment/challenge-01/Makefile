
build: docker-build docker-push challenge01-dist.tgz

docker-build: Dockerfile cake-of-paranoia-with-flag entrypoint.sh
	docker build -t potluckctf:challenge-01 .

docker-push:
	docker tag potluckctf:challenge-01 localhost:5001/potluckctf:challenge-01
	docker push localhost:5001/potluckctf:challenge-01

challenge01-dist.tgz: rootfs.tar.zst
	tar czvf challenge01-dist.tgz rootfs.tar.zst

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
	gsutil cp gs://potluckctf-challenge-1/solve-scripts .

.PHONY: build docker-build docker-push download
