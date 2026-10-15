.PHONY: build test install ui tui demo demo-clean

build:
	go build -o bin/kubectl-npmap ./cmd/kubectl-npmap

test:
	gofmt -l . && go vet ./... && go test ./...

install: build
	install -m 0755 bin/kubectl-npmap /usr/local/bin/kubectl-npmap

ui: build
	bin/kubectl-npmap ui

tui: build
	bin/kubectl-npmap tui

demo:
	kubectl apply -f demo/demo.yaml

demo-clean:
	kubectl delete -f demo/demo.yaml
