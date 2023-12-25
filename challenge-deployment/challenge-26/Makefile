CHALLENGE_ID = 26
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

docker-build: downloads/build
	docker build -t "$(LOCAL_IMAGE)" downloads/build

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge26-dist.tgz: downloads/build/out
	tar -C downloads/build/out -czvf challenge26-dist.tgz chal libc.so.6 ld-linux-x86-64.so.2

clean:
	rm -fr downloads/

download: downloads/build downloads/Dockerfile downloads/chal downloads/flag.txt

downloads:
	mkdir -p downloads

downloads/build: downloads
	gcloud storage cp -r $(DELIVERY_BUCKET)/build downloads/

downloads/Dockerfile: downloads
	gcloud storage cp -r $(DELIVERY_BUCKET)/Dockerfile downloads/

downloads/chal: downloads
	gcloud storage cp -r $(DELIVERY_BUCKET)/chal downloads/

downloads/flag.txt: downloads
	gcloud storage cp -r $(DELIVERY_BUCKET)/flag.txt downloads/


.PHONY: build docker-build docker-push dist dist-push download