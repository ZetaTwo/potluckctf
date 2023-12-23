CHALLENGE_ID = 11
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge11-dist.tgz

# TODO: multiple images
docker-build: DOCKER-DEPENDENCIES
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge11-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge11-dist.tgz DIST-DEPENDENCIES TODO

clean:
	rm -fr .env docker-compose.yml solve.py bot/ php/

download: .env docker-compose.yml solve.py bot/ php/

.env:
	gsutil cp gs://potluckctf-challenge-11/.env .
docker-compose.yml:
	gsutil cp gs://potluckctf-challenge-11/docker-compose.yml .
solve.py:
	gsutil cp gs://potluckctf-challenge-11/solve.py .
bot/:
	gsutil cp -r gs://potluckctf-challenge-11/bot/ .
php/:
	gsutil cp -r gs://potluckctf-challenge-11/php/ .

.PHONY: build docker-build docker-push download
