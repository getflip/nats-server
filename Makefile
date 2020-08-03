dockerImage = getflip/nats-server:$${VERSION:?Which version?}
publish: build
	docker push getflip/${dockerImage}
.PHONY: publish

build:
	docker build -f docker/Dockerfile.alpine . -t ${dockerImage}
.PHONY: build

run:
	docker run --rm -p 4221:4221 ${dockerImage}
