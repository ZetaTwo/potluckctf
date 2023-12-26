CHALLENGE_ID = 07
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-7

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

docker-build: deploy
	docker build -t $(LOCAL_IMAGE) deploy/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): public
	tar -C public/ -czvf $(DIST_FILE) bear_err.zip

clean:
	rm -fr deploy/ public/ solution/

download: deploy/ public/ solution/

deploy:
	gcloud storage cp -r $(DELIVERY_BUCKET)/deploy/ .

public:
	gcloud storage cp -r $(DELIVERY_BUCKET)/public/ .

solution/:
	gcloud storage cp -r $(DELIVERY_BUCKET)/solution/ .

.PHONY: build docker-build docker-push dist dist-push download
