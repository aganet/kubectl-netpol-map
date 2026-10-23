.PHONY: build test install ui tui demo demo-clean

# kubectl runs kubectl-netpol_map (underscore) for `kubectl netpol-map`.
build:
	go build -o bin/kubectl-netpol_map ./cmd/kubectl-netpol_map

test:
	gofmt -l . && go vet ./... && go test ./...

install:
	go install ./cmd/kubectl-netpol_map

ui: build
	bin/kubectl-netpol_map ui

tui: build
	bin/kubectl-netpol_map tui

demo:
	kubectl apply -f demo/demo.yaml

demo-clean:
	kubectl delete -f demo/demo.yaml
