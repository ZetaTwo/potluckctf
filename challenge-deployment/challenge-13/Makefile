CHALLENGE_ID = 13
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

docker-build: flag.txt chall.py config.el
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): chall.py config.el Dockerfile compose.yaml
	tar czvf $(DIST_FILE) chall.py config.el Dockerfile compose.yaml

clean:
	rm -f Dockerfile build_instructions.md chall.py compose.yaml config.el flag.txt solution.org solve.py

download: Dockerfile build_instructions.md chall.py compose.yaml config.el flag.txt solution.org solve.py

Dockerfile:
	gcloud storage cp $(DELIVERY_BUCKET)/Dockerfile .

build_instructions.md:
	gcloud storage cp $(DELIVERY_BUCKET)/build_instructions.md .

chall.py:
	gcloud storage cp $(DELIVERY_BUCKET)/chall.py .

compose.yaml:
	gcloud storage cp $(DELIVERY_BUCKET)/compose.yaml .

config.el:
	gcloud storage cp $(DELIVERY_BUCKET)/config.el .

flag.txt:
	gcloud storage cp $(DELIVERY_BUCKET)/flag.txt .

solution.org:
	gcloud storage cp $(DELIVERY_BUCKET)/solution.org .

solve.py:
	gcloud storage cp $(DELIVERY_BUCKET)/solve.py .

.PHONY: build docker-build docker-push dist dist-push download
