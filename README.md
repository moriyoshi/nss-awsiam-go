# nss_awsiam_go

This is a glibc NSS (name server switch) module, which does the query against AWS IAM user and group registry.

## Building

```
$ make
```

will produce `libnss_awsiam_go.so` in the current working directory.  You can put it under `/lib/x86_64-linux-gnu` (may vary by the configuration of your OS) as `libnss_awsiam_go.so.2` to get it to work.

## Configuration

Configuration is done through the configuration variable file (`/etc/nss_awsiam_go.conf`).

For security reasons, this module doesn't accept shared configuration and credentials under `~/.aws`.

## Configuration variables

### Authorization

In addition to the default AWS SDK configuration scheme, it supports STS credentials for a assumed role through the following environment variables:

* `AWS_STS_ASSUME_ROLE_ARN`

  This specifies the ARN for the assumed (target) IAM role. The difference from `AWS_ROLE_ARN` is that this can be used in nested STS contexts.

### Querying

You can configure the querying behavior by the following special environment variable:

* `NSS_AWSIAM_GO_TIMEOUT`

    Specifies the timeout value of the query. Defaults to 3 seconds.

### Debugging

* `NSS_AWSIAM_GO_DEBUG`

    Takes an integer value. 1 to enable error reporting, and 2 to enable AWS API request debugging.

### Miscellaneous

* `NSS_AWSIAM_GO_DEFAULT_SHELL`

    Specify the default shell for all users.

* `NSS_AWSIAM_GO_HOMEDIR_TEMPLATE`

    Specify the home directory template applied for all users.  You can use the placeholder `{userName}`, `{userId}`, or `{uid}` everywhere in the template.

## Configuration at the AWS side

The following IAM permissions are necessary to grant to the IAM role with which the instance (or container) runs.

* `iam:GetGroup`
* `iam:GetGroupsForUser`
* `iam:GetSSHPublicKey`
* `iam:GetUser`
* `iam:ListUser`
* `iam:ListGroup`

## Note on `SIGURG` usage in Go runtime

Since Go 1.14, it started to use `SIGURG` to do the non-cooperative preemption. This may be troublesome because the hosting application will also receive the signal. This module should work without preemption. To prevent the preemption, specify `GODEBUG=asyncpreemptoff=1`.

## License

MIT License
