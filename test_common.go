package main

import "github.com/mguentner/passwordless/test"

func DefaultConfig() Config {
	return Config{
		Config: test.DefaultConfig(),
		StorageOptions: StorageOptions{
			MaxKeysPerAccount: 0,
			MaxValueSizeBytes: 0,
		},
	}
}
