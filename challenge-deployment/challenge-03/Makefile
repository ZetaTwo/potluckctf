CHALLENGE_ID = 03
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-3

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

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
	gcloud storage cp $(DELIVERY_BUCKET)/Cargo.lock .

Cargo.toml:
	gcloud storage cp $(DELIVERY_BUCKET)/Cargo.toml .

ctf.xinetd:
	gcloud storage cp $(DELIVERY_BUCKET)/ctf.xinetd .

dist.tar.gz:
	gcloud storage cp $(DELIVERY_BUCKET)/dist.tar.gz .

Dockerfile:
	gcloud storage cp $(DELIVERY_BUCKET)/Dockerfile .

flag.txt:
	gcloud storage cp $(DELIVERY_BUCKET)/flag.txt .

solve:
	gcloud storage cp -r $(DELIVERY_BUCKET)/solve/ .

src:
	gcloud storage cp -r $(DELIVERY_BUCKET)/src/ .

start.sh:
	gcloud storage cp $(DELIVERY_BUCKET)/start.sh .

.PHONY: build docker-build docker-push dist dist-push download
