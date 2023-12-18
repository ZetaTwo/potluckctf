
build: docker-build

docker-build: Dockerfile cowsay.sh
	docker build -t potluckctf:challenge-00 .

docker-push:
	docker tag potluckctf:challenge-00 localhost:5001/potluckctf:challenge-00
	docker push localhost:5001/potluckctf:challenge-00

.PHONY: docker-build docker-push docker
