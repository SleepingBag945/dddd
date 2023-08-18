export LDFLAGS='-s -w '

GOOS=windows GOARCH=amd64 go build -ldflags="$LDFLAGS" -trimpath -o dddd.exe main.go
GOOS=linux GOARCH=amd64 go build -ldflags="$LDFLAGS" -trimpath -o dddd main.go