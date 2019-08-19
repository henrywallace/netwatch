#!/bin/sh

set -ex

go install ./...
go mod tidy

go install honnef.co/go/tools/cmd/staticcheck

go vet ./...
staticcheck ./...

go test ./...

shellcheck $(find . -name '*.sh')
