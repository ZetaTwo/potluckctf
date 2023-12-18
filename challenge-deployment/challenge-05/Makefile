
build: docker-build docker-push challenge05-dist.tgz

docker-build: docker/
	docker build -t potluckctf:challenge-05 docker/

docker-push:
	docker tag potluckctf:challenge-05 localhost:5001/potluckctf:challenge-05
	docker push localhost:5001/potluckctf:challenge-05

challenge05-dist.tgz: DIST-DEPENDENCIES # TODO
	tar czvf challenge05-dist.tgz DIST-DEPENDENCIES

clean:
	rm -fr docker/ exp/ README.md

download: docker/ exp/ README.md

README.md:
	gsutil cp gs://potluckctf-challenge-5/challenge/README.md .

docker/:
	gsutil cp -r gs://potluckctf-challenge-5/challenge/docker/ .

exp/:
	gsutil cp -r gs://potluckctf-challenge-5/challenge/exp/ .

.PHONY: build docker-build docker-push download
