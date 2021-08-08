package main

import (
	"github.com/mguentner/passwordless/config"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type StorageOptions struct {
	MaxKeysPerAccount uint64 `yaml:"maxKeysPerAccount"`
	MaxValueSizeBytes uint64 `yaml:"maxValueSizeBytes"`
}

type Config struct {
	config.Config  `yaml:",inline"`
	StorageOptions StorageOptions `yaml:"storageOptions"`
}

func (c Config) Validate() error {
	err := c.Config.Validate()
	if err != nil {
		return err
	}
	return nil
}

func (e Config) GetConfig() *config.Config {
	return &e.Config
}

func ReadConfigFromFile(path string) (*Config, error) {
	var config Config

	yml, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yml, &config)
	if err != nil {
		return nil, err
	}
	err = config.Validate()
	if err != nil {
		return &config, err
	}
	return &config, nil
}
