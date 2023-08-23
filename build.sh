#!/bin/bash

# 64位 Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ./releases/dddd64.exe -ldflags "-s -w" main.go
upx -9 ./releases/dddd64.exe

# 32位 Windows
GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -o ./releases/dddd32.exe -ldflags "-s -w" main.go
upx -9 ./releases/dddd32.exe

# 64位 Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ./releases/dddd64 -ldflags "-s -w" main.go
upx -9 ./releases/dddd64

# 32位 Linux
GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -o ./releases/dddd32 -ldflags "-s -w" main.go
upx -9 ./releases/dddd32

# 64位 darwin_amd64
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o ./releases/dddd_darwin_amd64
 -ldflags "-s -w" main.go
upx -9 ./releases/dddd_darwin_amd64