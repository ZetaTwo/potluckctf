CHALLENGE_ID = 24
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

docker-build: public
	docker build --build-arg FLAG=potluck{concocted_cyber_casserole} -t $(LOCAL_IMAGE) public

docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(REMOTE_IMAGE)
	docker push $(REMOTE_IMAGE)

$(DIST_FILE): public
	tar -C public -czvf $(DIST_FILE) . 

clean:
	rm -fr README.md public.tgz solve.py public/

download: README.md public.tgz solve.py public/

README.md:
	gcloud storage cp $(DELIVERY_BUCKET)/README.md .

public.tgz:
	gcloud storage cp $(DELIVERY_BUCKET)/public.tgz .

solve.py:
	gcloud storage cp $(DELIVERY_BUCKET)/solve.py .

public:
	gcloud storage cp -r $(DELIVERY_BUCKET)/public .

.PHONY: build docker-build docker-push dist dist-push download
