
build: docker-build docker-push challenge07-dist.tgz

docker-build: deploy/
	docker build -t potluckctf:challenge-07 deploy/

docker-push:
	docker tag potluckctf:challenge-07 localhost:5001/potluckctf:challenge-07
	docker push localhost:5001/potluckctf:challenge-07

challenge07-dist.tgz: public/
	tar -C public/ -czvf challenge07-dist.tgz bear_err.zip

clean:
	rm -fr deploy/ public/ solution/

download: deploy/ public/ solution/

deploy/:
	gsutil cp -r gs://potluckctf-challenge-7/deploy/ .

public/:
	gsutil cp -r gs://potluckctf-challenge-7/public/ .

solution/:
	gsutil cp -r gs://potluckctf-challenge-7/solution/ .

.PHONY: build docker-build docker-push download
