export LDFLAGS='-s -w '

# windows x64
GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -trimpath -o dddd64.exe main.go
upx -9 dddd64.exe

# windows x86
GOOS=windows GOARCH=386 go build -ldflags="$LDFLAGS" -trimpath -o dddd.exe main.go
upx -9 dddd.exe

# linux amd64
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -trimpath -o dddd_linux64 main.go
upx -9 dddd_linux64

# linux arm64
GOOS=linux GOARCH=arm64 go build -ldflags="$LDFLAGS" -trimpath -o dddd_linux_arm64 main.go

# darwin amd64
GOOS=darwin GOARCH=amd64 go build -ldflags="$LDFLAGS" -trimpath -o dddd_darwin64 main.go

# darwin arm64
GOOS=darwin GOARCH=arm64 go build -ldflags="$LDFLAGS" -trimpath -o dddd_darwin_arm64 main.go