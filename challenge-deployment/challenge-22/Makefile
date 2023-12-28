CHALLENGE_ID = 22
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push challenge22-dist.tgz

sekurbut-image: sekurbut.tar
	docker load -i sekurbut.tar

docker-build-pre: sekurbut-image
	docker build -t sekurbut2 -f Dockerfile .

docker-build: docker-build-pre flagloader2.hex
	docker build -t $(LOCAL_IMAGE) -f v2.Dockerfile .

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge22-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge22-dist.tgz DIST-DEPENDENCIES

clean:
	rm -f sekurbut.tar flagloader2.hex

download: sekurbut.tar flagloader2.hex

flagloader2.hex:
	gcloud storage cp $(DELIVERY_BUCKET)/flagloader2.hex .

sekurbut.tar:
	gcloud storage cp $(DELIVERY_BUCKET)/sekurbut.tar .

.PHONY: build docker-build docker-push dist dist-push download
