CHALLENGE_ID = 07
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-7

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: deploy/
	docker build -t $(LOCAL_IMAGE) deploy/

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): public/
	tar -C public/ -czvf $(DIST_FILE) bear_err.zip

clean:
	rm -fr deploy/ public/ solution/

download: deploy/ public/ solution/

deploy/:
	gsutil cp -r $(DELIVERY_BUCKET)/deploy/ .

public/:
	gsutil cp -r $(DELIVERY_BUCKET)/public/ .

solution/:
	gsutil cp -r $(DELIVERY_BUCKET)/solution/ .

.PHONY: build docker-build docker-push dist dist-push download
