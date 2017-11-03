DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=akroh/go-ebpf-builder
UID=$(shell id -u)
GID=$(shell id -g)
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: execsnoop

check:
	@go get golang.org/x/tools/cmd/goimports
	@goimports -l -local github.com/andrewkroh . | (! grep .) || (echo "Code differs from goimports' style ^" && false)
	@go run scripts/check_copyright.go .

fmt:
	@goimports -l -w -local github.com/andrewkroh .

clean:
	@rm -rf build cmd/execsnoop/execsnoop
	@find . -name '*.o' -exec rm {} \;

build_dir:
	@mkdir -p build/bin
	@mkdir -p build/test

execsnoop: build_dir
	$(MAKE) -C exec/bpf
	go build -o build/bin/execsnoop ./cmd/execsnoop 

execsnoop-test: build_dir
	go test -c ./exec/ -o build/test/exec.test
	sudo build/test/exec.test -test.v

# For building inside of a Docker environment.
docker-all: build-docker-image
	$(SUDO) docker run --rm \
		-v $(PWD):/go/src/github.com/andrewkroh/go-ebpf \
		--workdir=/go/src/github.com/andrewkroh/go-ebpf \
		$(DOCKER_IMAGE) \
		make all
	# Fixing permissions on files generated in Docker.
	sudo chown -R $(UID):$(GID) .

docker-run:
	$(SUDO) docker run -it --rm \
		-v $(PWD):/go/src/github.com/andrewkroh/go-ebpf \
		--workdir=/go/src/github.com/andrewkroh/go-ebpf \
		$(DOCKER_IMAGE) /bin/bash

build-docker-image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

delete-docker-image:
	$(SUDO) docker rmi -f $(DOCKER_IMAGE)
