.PHONY: build test vuln release snapshot install ui tui demo demo-clean

# kubectl runs kubectl-netpol_map (underscore) for `kubectl netpol-map`.
build:
	go build -o bin/kubectl-netpol_map ./cmd/kubectl-netpol_map

test:
	test -z "$$(gofmt -l .)" && go vet ./... && go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./... && go test -race ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Local release: tag first (git tag vX.Y.Z && git push --tags), then run with a
# GITHUB_TOKEN that can write releases. Builds every platform and uploads the
# archives and checksums.txt to the GitHub release for that tag.
release: test vuln
	go run github.com/goreleaser/goreleaser/v2@latest release --clean

# The same archives into dist/, without a tag or a token, to check a build.
snapshot:
	go run github.com/goreleaser/goreleaser/v2@latest release --clean --snapshot

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
