#!/bin/sh
ln -s ${PWD}/libnss_awsiam_go.so /lib/x86_64-linux-gnu/libnss_awsiam_go.so.2

ls -l /lib/x86_64-linux-gnu/

cat > "/etc/nss_awsiam_go.conf" <<'HERE'
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=SECRET
AWS_ENDPOINT_OVERRIDES_IAM=http://localhost:9000
AWS_DEFAULT_REGION=us-east-1
NSS_AWSIAM_GO_DEBUG=1
HERE

sed -i -e 's/^\(\(passwd\|group\|shadow\): .*\)$/\1 awsiam_go/' '/etc/nsswitch.conf'
cat /etc/nsswitch.conf

./iam-emulator-bin -bind 'localhost:9000' testfixture.yml &
emulator_pid=$!

getent passwd --service=awsiam_go
getent group --service=awsiam_go

id foo
getent passwd --service=awsiam_go foo
id bar
getent passwd --service=awsiam_go bar

kill -TERM "${emulator_pid}"