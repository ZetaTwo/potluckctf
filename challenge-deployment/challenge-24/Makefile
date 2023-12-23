CHALLENGE_ID = 24
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge24-dist.tgz

docker-build: public
	docker build -t $(LOCAL_IMAGE) public

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge24-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge24-dist.tgz DIST-DEPENDENCIES TODO

clean:
	rm -fr README.md public.tgz solve.py public/

download: README.md public.tgz solve.py public/

README.md:
	gsutil cp gs://potluckctf-challenge-24/README.md .

public.tgz:
	gsutil cp gs://potluckctf-challenge-24/public.tgz .

solve.py:
	gsutil cp gs://potluckctf-challenge-24/solve.py .

public:
	gsutil cp -r gs://potluckctf-challenge-24/public .

.PHONY: build docker-build docker-push download
