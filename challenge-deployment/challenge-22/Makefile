CHALLENGE_ID = 22
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest

build: docker-build docker-push challenge22-dist.tgz

docker-build: sekurbut.tar
	docker import sekurbut.tar "$(LOCAL_IMAGE)"

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

challenge22-dist.tgz: DIST-DEPENDENCIES
	tar czvf challenge22-dist.tgz DIST-DEPENDENCIES

clean:
	rm -f sekurbut.tar

download: sekurbut.tar

sekurbut.tar:
	gsutil cp gs://potluckctf-challenge-22/sekurbut.tar .

.PHONY: build docker-build docker-push download
