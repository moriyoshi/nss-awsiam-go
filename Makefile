all: libnss_awsiam_go.so

clean:
	rm -f libnss_awsiam_go.so

libnss_awsiam_go.so: nss_awsiam.go client.go utils.go
	go build -o "$@" -buildmode=c-shared $^

aws-iam-emulator: ${GOPATH}/bin/aws-iam-emulator

${GOPATH}/bin/aws-iam-emulator:
	go get github.com/moriyoshi/aws-iam-emulator

test:
	docker run --rm -v "${PWD}:/go/src/stage:rw" -it "golang:1.15-buster" sh -c 'cd /go/src/stage && ls -l && make aws-iam-emulator libnss_awsiam_go.so && ./test.sh'

.PHONY: all clean aws-iam-emulator test
