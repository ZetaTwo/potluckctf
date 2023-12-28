CHALLENGE_ID = 08
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-8
DIST_FILE = challenge$(CHALLENGE_ID)-dist.tgz

build: terraform.txt dist

dist: $(DIST_FILE)

dist-push: dist
	gcloud storage cp $(DIST_FILE) gs://potluckctf

dist-url:
	gcloud storage sign-url --region europe --impersonate-service-account challenge-distribution@potluck-ctf.iam.gserviceaccount.com --duration 7d gs://potluckctf/$(DIST_FILE)

clean:
	rm -f ctfdescription.txt enchiladas.csv main.rs

download: ctfdescription.txt enchiladas.csv main.rs

$(DIST_FILE): enchiladas.mxc
	tar -czvf $(DIST_FILE) enchiladas.mxc

ctfdescription.txt:
	gcloud storage cp $(DELIVERY_BUCKET)/ctfdescription.txt .

terraform.txt: enchiladas.csv convert-terraform.py
	python3 convert-terraform.py enchiladas.csv > terraform.txt

enchiladas.csv:
	gcloud storage cp $(DELIVERY_BUCKET)/enchiladas.csv .

main.rs:
	gcloud storage cp $(DELIVERY_BUCKET)/main.rs .

.PHONY: build download
