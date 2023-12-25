CHALLENGE_ID = 04
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE_WIN = challenge$(CHALLENGE_ID)-windows-dist.tgz
DIST_FILE_MAC = challenge$(CHALLENGE_ID)-mac-dist.tgz
DIST_FILE_LINUX = challenge$(CHALLENGE_ID)-linux-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE_WIN) $(DIST_FILE_MAC) $(DIST_FILE_LINUX)

dist-push: dist
	gcloud storage cp $(DIST_FILE_WIN) $(DIST_FILE_MAC) $(DIST_FILE_LINUX) gs://potluckctf

docker-build: DOCKER-DEPENDENCIES
	docker build -t "$(LOCAL_IMAGE)" .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE_WIN): charming-circuit-challenge-windows.zip
	unzip charming-circuit-challenge-windows.zip
	tar czvf $(DIST_FILE_WIN) charming-circuit-challenge.exe
	rm charming-circuit-challenge.exe

$(DIST_FILE_MAC): charming-circuit-challenge-mac.zip
	unzip charming-circuit-challenge-mac.zip
	tar czvf $(DIST_FILE_MAC) charming-circuit-challenge
	rm charming-circuit-challenge

$(DIST_FILE_LINUX): charming-circuit-challenge-linux.zip
	unzip charming-circuit-challenge-linux.zip
	tar czvf $(DIST_FILE_LINUX) charming-circuit-challenge
	rm charming-circuit-challenge

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE_WIN)
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE_MAC)
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE_LINUX)

clean:
	rm -f charming-circuit-challenge-linux.zip charming-circuit-challenge-mac.zip charming-circuit-challenge-windows.zip

download: charming-circuit-challenge-linux.zip charming-circuit-challenge-mac.zip charming-circuit-challenge-windows.zip

charming-circuit-challenge-linux.zip:
	gcloud storage cp gs://potluckctf-challenge-4/charming-circuit-challenge-linux.zip .

charming-circuit-challenge-mac.zip:
	gcloud storage cp gs://potluckctf-challenge-4/charming-circuit-challenge-mac.zip .

charming-circuit-challenge-windows.zip:
	gcloud storage cp gs://potluckctf-challenge-4/charming-circuit-challenge-windows.zip .

.PHONY: build docker-build docker-push dist dist-push download
