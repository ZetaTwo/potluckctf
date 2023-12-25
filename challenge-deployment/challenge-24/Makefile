CHALLENGE_ID = 24
LOCAL_IMAGE = potluckctf:challenge-$(CHALLENGE_ID)
REMOTE_IMAGE = europe-west3-docker.pkg.dev/potluck-ctf/challenge$(CHALLENGE_ID)-repository/challenge$(CHALLENGE_ID):latest
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz
DELIVERY_BUCKET = gs://potluckctf-challenge-$(CHALLENGE_ID)

build: docker-build docker-push dist

dist: $(DIST_FILE)

dist-push: dist
	gsutil cp $(DIST_FILE) gs://potluckctf

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
	gsutil cp $(DELIVERY_BUCKET)/README.md .

public.tgz:
	gsutil cp $(DELIVERY_BUCKET)/public.tgz .

solve.py:
	gsutil cp $(DELIVERY_BUCKET)/solve.py .

public:
	gsutil cp -r $(DELIVERY_BUCKET)/public .

.PHONY: build docker-build docker-push dist dist-push download
