all: execsnoop

check:
	@goimports -l -local github.com/andrewkroh . | (! grep .) || (echo "Code differs from goimports' style ^" && false)

fmt:
	@goimports -l -w -local github.com/andrewkroh .

clean:
	@rm -rf build cmd/execsnoop/execsnoop
	@find . -name '*.o' -exec rm {} \;

build_dir:
	mkdir -p build/bin

execsnoop: build_dir
	$(MAKE) -C exec/bpf
	go build -o build/bin/execsnoop ./cmd/execsnoop 

