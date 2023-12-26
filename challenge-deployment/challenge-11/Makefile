CHALLENGE_ID = 11
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE_BOT = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID)-bot:latest
REMOTE_IMAGE_PHP = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID)-php:latest
REMOTE_IMAGE_NGINX = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID)-nginx:latest
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push

docker-build: docker-build-bot docker-build-php docker-build-nginx

docker-build-bot: bot
	docker build -t $(LOCAL_IMAGE)-bot -f bot/Dockerfile-bot bot

docker-build-php: php
	docker build -t $(LOCAL_IMAGE)-php -f php/Dockerfile-php php

docker-build-nginx: nginx
	docker build -t $(LOCAL_IMAGE)-nginx -f nginx/Dockerfile-nginx nginx

docker-push: docker-build
	docker tag $(LOCAL_IMAGE)-bot $(REMOTE_IMAGE_BOT)
	docker push $(REMOTE_IMAGE_BOT)

	docker tag $(LOCAL_IMAGE)-php $(REMOTE_IMAGE_PHP)
	docker push $(REMOTE_IMAGE_PHP)
	
	docker tag $(LOCAL_IMAGE)-nginx $(REMOTE_IMAGE_NGINX)
	docker push $(REMOTE_IMAGE_NGINX)

clean:
	rm -fr .env docker-compose.yml solve.py bot/ php/ nginx/

download: .env docker-compose.yml solve.py bot php nginx

.env:
	gcloud storage cp $(DELIVERY_BUCKET)/.env .

docker-compose.yml:
	gcloud storage cp $(DELIVERY_BUCKET)/docker-compose.yml .

solve.py:
	gcloud storage cp $(DELIVERY_BUCKET)/solve.py .

bot:
	gcloud storage cp -r $(DELIVERY_BUCKET)/bot/ .

nginx:
	gcloud storage cp -r $(DELIVERY_BUCKET)/nginx/ .

php:
	gcloud storage cp -r $(DELIVERY_BUCKET)/php/ .

.PHONY: build docker-build docker-push dist dist-push download