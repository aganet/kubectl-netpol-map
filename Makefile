.PHONY: build test install ui tui demo demo-clean

build:
	go build -o bin/kubectl-netpol-map ./cmd/kubectl-netpol-map

test:
	gofmt -l . && go vet ./... && go test ./...

install: build
	install -m 0755 bin/kubectl-netpol-map /usr/local/bin/kubectl-netpol-map

ui: build
	bin/kubectl-netpol-map ui

tui: build
	bin/kubectl-netpol-map tui

demo:
	kubectl apply -f demo/demo.yaml

demo-clean:
	kubectl delete -f demo/demo.yaml
