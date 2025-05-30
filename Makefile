.PHONY: all build clean

all: build

build:
	go build -o trust-validator main.go

clean:
	rm -f trust-validator
