CHALLENGE_ID = 13
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge13-dist.tgz

docker-build: flag.txt chall.py config.el
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge13-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge13-dist.tgz DIST-DEPENDENCIES

clean:
	rm -f Dockerfile build_instructions.md chall.py compose.yaml config.el flag.txt solution.org solve.py

download: Dockerfile build_instructions.md chall.py compose.yaml config.el flag.txt solution.org solve.py

Dockerfile:
	gsutil cp gs://potluckctf-challenge-13/Dockerfile .

build_instructions.md:
	gsutil cp gs://potluckctf-challenge-13/build_instructions.md .

chall.py:
	gsutil cp gs://potluckctf-challenge-13/chall.py .

compose.yaml:
	gsutil cp gs://potluckctf-challenge-13/compose.yaml .

config.el:
	gsutil cp gs://potluckctf-challenge-13/config.el .

flag.txt:
	gsutil cp gs://potluckctf-challenge-13/flag.txt .

solution.org:
	gsutil cp gs://potluckctf-challenge-13/solution.org .

solve.py:
	gsutil cp gs://potluckctf-challenge-13/solve.py .

.PHONY: build docker-build docker-push download
