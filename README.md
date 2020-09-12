# nss_awsiam_go

This is a glibc NSS (name server switch) module, which does the query against AWS IAM user and group registry.

## Building

```
$ make
```

will produce `libnss_awsiam_go.so` in the current working directory.  You can put it under `/lib/x86_64-linux-gnu` (may vary by the configuration of your OS) as `libnss_awsiam_go.so.2` to get it to work.

## Configuration

Configuration is done through the env file (`/etc/nss_awsiam_go.conf`) or environment variables.

For security reasons, this module doesn't accept shared configuration and credentials under `~/.aws`.

## Environment variables

### Querying

You can configure the querying behavior by the following special environment variable:

* `NSS_AWSIAM_GO_TIMEOUT`

    Specifies the timeout value of the query. Defaults to 3 seconds.

### Debugging

* `NSS_AWSIAM_GO_DEBUG`

    Takes an integer value. 1 to enable error reporting, and 2 to enable AWS API request debugging.

## License

MIT License
