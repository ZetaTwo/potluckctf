CHALLENGE_ID = 16
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: DOCKER-DEPENDENCIES
	docker build -t "$(LOCAL_IMAGE)" .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): dist/upside_down_cake.py
	tar -C dist/ -czvf $(DIST_FILE) upside_down_cake.py

clean:
	rm -fr dist solve

download: dist solve

dist:	
	gsutil cp -r $(DELIVERY_BUCKET)/dist/ .

solve:	
	gsutil cp -r $(DELIVERY_BUCKET)/solve/ .

.PHONY: build docker-build docker-push download
