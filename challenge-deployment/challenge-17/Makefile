CHALLENGE_ID = 17
REMOTE_IMAGE_CONTROLLER = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID)-controller:latest
REMOTE_IMAGE_INTERFACE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID)-interface:latest
REMOTE_IMAGE_HEATER = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID)-heater:latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push

docker-build: docker-build-controller docker-build-interface docker-build-heater

docker-build-controller: image-controller.tar.gz
	docker load -i image-controller.tar.gz

docker-build-interface: image-interface.tar.gz
	docker load -i image-interface.tar.gz

docker-build-heater: image-heater.tar.gz
	docker load -i image-heater.tar.gz

docker-push: docker-build
	docker tag controller:latest $(REMOTE_IMAGE_CONTROLLER)
	docker push $(REMOTE_IMAGE_CONTROLLER)

	docker tag interface:latest $(REMOTE_IMAGE_INTERFACE)
	docker push $(REMOTE_IMAGE_INTERFACE)
	
	docker tag heater:latest $(REMOTE_IMAGE_HEATER)
	docker push $(REMOTE_IMAGE_HEATER)

$(DIST_FILE): DIST-DEPENDENCIES
	tar czvf $(DIST_FILE) DIST-DEPENDENCIES

clean:
	rm -f docker-compose.yml image-controller.tar.gz image-heater.tar.gz image-interface.tar.gz

download: docker-compose.yml image-controller.tar.gz image-heater.tar.gz image-interface.tar.gz

docker-compose.yml:
	gcloud storage cp $(DELIVERY_BUCKET)/docker-compose.yml .

image-controller.tar.gz:
	gcloud storage cp $(DELIVERY_BUCKET)/image-controller.tar.gz .

image-heater.tar.gz:
	gcloud storage cp $(DELIVERY_BUCKET)/image-heater.tar.gz .

image-interface.tar.gz:
	gcloud storage cp $(DELIVERY_BUCKET)/image-interface.tar.gz .

.PHONY: build docker-build docker-push dist dist-push download
