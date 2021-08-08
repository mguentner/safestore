# safestore

store arbitrary data under a key authenticated using e-mail accounts (passwordless).

Authentication only needs to happen once as long as the client can (locally store) the
refresh token and also refreshes regularly.

# Usage

Create a set of keys using `create_signing_keys.sh`.

Example:

```
$ ./create_signing_keys.sh testKeys
```

Copy `config.sample.yaml` to `config.yaml` and adjust for your needs.
The key directory is set using the `keyPath` option.

Check `config/config.go` for comments on other options.
Adjust `maxKeysPerAccount` and `maxValueSizeBytes` if desired.
Run the application using `./safestore --configPath config.yaml`

Small implementation detail: Not optimized for handling large data (many 100's MegaBytes).

# Copyright and License

AGPLv3 (see LICENSE)

2021 Maximilian Güntner <code@mguentner.de>
