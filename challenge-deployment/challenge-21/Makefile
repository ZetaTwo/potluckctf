CHALLENGE_ID = 21
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

docker-build: potluck_Schrodinger's\ P1G
	docker build -t "$(LOCAL_IMAGE)" "potluck_Schrodinger's P1G/deploy"

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): potluck_Schrodinger's\ P1G
	tar -C "potluck_Schrodinger's P1G/attachment" -czvf $(DIST_FILE) myP1G.zip

clean:
	rm -rf "potluck_Schrodinger's P1G" potluck_Schrodingers_P1G.zip

download: potluck_Schrodingers_P1G.zip

potluck_Schrodinger's\ P1G: potluck_Schrodingers_P1G.zip
	unzip potluck_Schrodingers_P1G.zip

potluck_Schrodingers_P1G.zip:
	gcloud storage cp $(DELIVERY_BUCKET)/potluck_Schrodingers_P1G.zip .


.PHONY: build docker-build docker-push dist dist-push download
