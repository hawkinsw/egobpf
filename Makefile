all:
	go build -race -o egobpf ./cmd/cmd.go
	objdump -d -Mintel egobpf > egobpf.obj
