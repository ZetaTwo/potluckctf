CHALLENGE_ID = 03
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-3

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: Dockerfile Cargo.lock Cargo.toml flag.txt src start.sh ctf.xinetd
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): dist.tar.gz
	cp dist.tar.gz $(DIST_FILE)

clean:
	rm -rf Dockerfile Cargo.lock Cargo.toml ctf.xinetd dist.tar.gz Dockerfile flag.txt solve src start.sh 

download: Dockerfile Cargo.lock Cargo.toml ctf.xinetd dist.tar.gz Dockerfile flag.txt solve src start.sh 

Cargo.lock:
	gsutil cp $(DELIVERY_BUCKET)/Cargo.lock .

Cargo.toml:
	gsutil cp $(DELIVERY_BUCKET)/Cargo.toml .

ctf.xinetd:
	gsutil cp $(DELIVERY_BUCKET)/ctf.xinetd .

dist.tar.gz:
	gsutil cp $(DELIVERY_BUCKET)/dist.tar.gz .

Dockerfile:
	gsutil cp $(DELIVERY_BUCKET)/Dockerfile .

flag.txt:
	gsutil cp $(DELIVERY_BUCKET)/flag.txt .

solve:
	gsutil cp -r $(DELIVERY_BUCKET)/solve/ .

src:
	gsutil cp -r $(DELIVERY_BUCKET)/src/ .

start.sh:
	gsutil cp $(DELIVERY_BUCKET)/start.sh .

.PHONY: build docker-build docker-push dist dist-push download
