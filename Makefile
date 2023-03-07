dockerImage = flipistry.azurecr.io/flipnext/nats-server:1.3_2023-03-07_16-30-28
publish: build
	docker push ${dockerImage}
.PHONY: publish

build:
	docker build -f docker/Dockerfile.alpine . -t ${dockerImage}
.PHONY: build

run:
	docker run --rm -p 4221:4221 ${dockerImage}
