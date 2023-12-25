CHALLENGE_ID = 29
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

docker-build: Dockerfile server.py requirements.txt
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): challenge29-dist.tar.gz
	cp challenge29-dist.tar.gz $(DIST_FILE)

clean:
	rm -f challenge29-dist.tar.gz service.tar.gz docker-compose.yml Dockerfile server.py requirements.txt

download: challenge29-dist.tar.gz service.tar.gz

challenge29-dist.tar.gz:
	gcloud storage cp $(DELIVERY_BUCKET)/challenge29-dist.tar.gz .

service.tar.gz:
	gcloud storage cp $(DELIVERY_BUCKET)/service.tar.gz .

docker-compose.yml: service.tar.gz
	tar xf service.tar.gz

Dockerfile: service.tar.gz
	tar xf service.tar.gz

server.py: service.tar.gz
	tar xf service.tar.gz

requirements.txt: service.tar.gz
	tar xf service.tar.gz

.PHONY: build docker-build docker-push dist dist-push download
