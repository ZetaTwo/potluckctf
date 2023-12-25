CHALLENGE_ID = 13
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

docker-build: flag.txt chall.py config.el
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): DIST-DEPENDENCIES
	tar czvf $(DIST_FILE) DIST-DEPENDENCIES TODO

clean:
	rm -f Dockerfile build_instructions.md chall.py compose.yaml config.el flag.txt solution.org solve.py

download: Dockerfile build_instructions.md chall.py compose.yaml config.el flag.txt solution.org solve.py

Dockerfile:
	gsutil cp $(DELIVERY_BUCKET)/Dockerfile .

build_instructions.md:
	gsutil cp $(DELIVERY_BUCKET)/build_instructions.md .

chall.py:
	gsutil cp $(DELIVERY_BUCKET)/chall.py .

compose.yaml:
	gsutil cp $(DELIVERY_BUCKET)/compose.yaml .

config.el:
	gsutil cp $(DELIVERY_BUCKET)/config.el .

flag.txt:
	gsutil cp $(DELIVERY_BUCKET)/flag.txt .

solution.org:
	gsutil cp $(DELIVERY_BUCKET)/solution.org .

solve.py:
	gsutil cp $(DELIVERY_BUCKET)/solve.py .

.PHONY: build docker-build docker-push dist dist-push download
