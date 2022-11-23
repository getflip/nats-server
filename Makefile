dockerImage = flipistry.azurecr.io/flipnext/nats-server:1.3_2022-11-23_17-48-28
publish: build
	docker push ${dockerImage}
.PHONY: publish

build:
	docker build -f docker/Dockerfile.alpine . -t ${dockerImage}
.PHONY: build

run:
	docker run --rm -p 4221:4221 ${dockerImage}
