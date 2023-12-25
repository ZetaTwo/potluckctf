CHALLENGE_ID = 11
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push

# TODO: multiple images
docker-build: DOCKER-DEPENDENCIES
	docker build -t $(LOCAL_IMAGE) .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

clean:
	rm -fr .env docker-compose.yml solve.py bot/ php/

download: .env docker-compose.yml solve.py bot/ php/

.env:
	gsutil cp $(DELIVERY_BUCKET)/.env .
docker-compose.yml:
	gsutil cp $(DELIVERY_BUCKET)/docker-compose.yml .
solve.py:
	gsutil cp $(DELIVERY_BUCKET)/solve.py .
bot/:
	gsutil cp -r $(DELIVERY_BUCKET)/bot/ .
php/:
	gsutil cp -r $(DELIVERY_BUCKET)/php/ .

.PHONY: build docker-build docker-push dist dist-push download