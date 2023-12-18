
build: docker-build docker-push challenge03-dist.tgz

docker-build: Dockerfile Cargo.lock Cargo.toml flag.txt src start.sh ctf.xinetd
	docker build -t potluckctf:challenge-03 .

docker-push:
	docker tag potluckctf:challenge-03 localhost:5001/potluckctf:challenge-03
	docker push localhost:5001/potluckctf:challenge-03

challenge03-dist.tgz: dist.tar.gz
	cp dist.tar.gz challenge03-dist.tgz

clean:
	rm -rf Dockerfile Cargo.lock Cargo.toml ctf.xinetd dist.tar.gz Dockerfile flag.txt solve src start.sh 

download: Dockerfile Cargo.lock Cargo.toml ctf.xinetd dist.tar.gz Dockerfile flag.txt solve src start.sh 

Cargo.lock:
	gsutil cp gs://potluckctf-challenge-3/Cargo.lock .

Cargo.toml:
	gsutil cp gs://potluckctf-challenge-3/Cargo.toml .

ctf.xinetd:
	gsutil cp gs://potluckctf-challenge-3/ctf.xinetd .

dist.tar.gz:
	gsutil cp gs://potluckctf-challenge-3/dist.tar.gz .

Dockerfile:
	gsutil cp gs://potluckctf-challenge-3/Dockerfile .

flag.txt:
	gsutil cp gs://potluckctf-challenge-3/flag.txt .

solve:
	gsutil cp -r gs://potluckctf-challenge-3/solve/ .

src:
	gsutil cp -r gs://potluckctf-challenge-3/src/ .

start.sh:
	gsutil cp gs://potluckctf-challenge-3/start.sh .

.PHONY: build docker-build docker-push download
