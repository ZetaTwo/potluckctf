CHALLENGE_ID = 30
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DELIVERY_BUCKET = gs://potluckctf-challenge-22

build: docker-build docker-push challenge22-dist.tgz

sekurbut-image: sekurbut.tar
	docker load -i sekurbut.tar

docker-build: sekurbut-image
	docker build -t $(LOCAL_IMAGE) .

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
