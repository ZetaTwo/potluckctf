
build: docker-build docker-push challengeXX-dist.tgz

docker-build: DOCKER-DEPENDENCIES
	docker build -t potluckctf:challenge-XX .

docker-push:
	docker tag potluckctf:challenge-XX localhost:5001/potluckctf:challenge-XX
	docker push localhost:5001/potluckctf:challenge-XX

challengeXX-dist.tgz: DIST-DEPENDENCIES
	tar czvf challengeXX-dist.tgz DIST-DEPENDENCIES

clean:
	rm -f FILES

download: FILES

A-FILE:
	gsutil cp gs://potluckctf-challenge-X/A-FILE .


.PHONY: build docker-build docker-push download
