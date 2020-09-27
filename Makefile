all: libnss_awsiam_go.so

clean:
	rm -f libnss_awsiam_go.so

libnss_awsiam_go.so: nss_awsiam.go client.go utils.go
	go build -o "$@" -buildmode=c-shared $^

iam-emulator-bin: iam-emulator/*.go
	go build -o "$@" ./iam-emulator

test:
	docker run --rm -v "${PWD}:/go/src/stage:rw" -it "golang:1.15-buster" sh -c 'cd /go/src/stage && ls -l && make iam-emulator-bin libnss_awsiam_go.so && ./test.sh'

.PHONY: all clean test
