all: libnss_awsiam_go.so

clean:
	rm -f libnss_awsiam_go.so

libnss_awsiam_go.so: nss_awsiam.go client.go 
	go build -o "$@" -buildmode=c-shared $^

.PHONY: all clean
