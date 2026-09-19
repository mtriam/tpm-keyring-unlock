#!/bin/sh

gofmt -w main.go main_test.go &&
go test ./... &&
CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o tpm-keyring-unlock .
