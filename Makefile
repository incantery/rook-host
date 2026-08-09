# rook-host: schema authority + host-side core.

.PHONY: test
test:
	go vet ./...
	go test -race ./...

# Regenerate gen/ from proto/. Plugins run LOCALLY and are pinned by
# go.mod's versions, so generated code and library can never drift
# apart, and generation needs no network beyond `go install`.
.PHONY: proto
proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$$(go list -m -f '{{.Version}}' google.golang.org/protobuf)
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@$$(go list -m -f '{{.Version}}' connectrpc.com/connect)
	buf lint
	buf generate

.PHONY: lint
lint:
	buf lint

# Wire compatibility against main. A deployed host keeps speaking an
# old build for as long as it likes, so FILE-level compatibility is a
# hard requirement.
.PHONY: breaking
breaking:
	buf breaking --against '.git#branch=main'
