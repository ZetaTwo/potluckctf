CHALLENGE_ID = 08
# No leading zero
DELIVERY_BUCKET = gs://potluckctf-challenge-8

build: terraform.txt

clean:
	rm -f ctfdescription.txt enchiladas.csv main.rs

download: ctfdescription.txt enchiladas.csv main.rs

ctfdescription.txt:
	gcloud storage cp $(DELIVERY_BUCKET)/ctfdescription.txt .

terraform.txt: enchiladas.csv convert-terraform.py
	python3 convert-terraform.py enchiladas.csv > terraform.txt

enchiladas.csv:
	gcloud storage cp $(DELIVERY_BUCKET)/enchiladas.csv .

main.rs:
	gcloud storage cp $(DELIVERY_BUCKET)/main.rs .

.PHONY: build download
