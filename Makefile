build:
	go build -ldflags="-s -w -H=windowsgui" advancedreverseshell.go
	go build master.go