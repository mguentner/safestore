package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/dgraph-io/badger/v3"
	"github.com/mguentner/passwordless/state"
	"github.com/rs/zerolog/log"
)

type ErrKeyLimitReached struct{}

func (e *ErrKeyLimitReached) Error() string {
	return "KeyLimitReached"
}

type ErrDataTooBig struct{}

func (e *ErrDataTooBig) Error() string {
	return "DataTooBig"
}

type ErrKeyNotFound struct{}

func (e *ErrKeyNotFound) Error() string {
	return "KeyNotFound"
}

func keysForIdentifier(identifier string, txn *badger.Txn) []string {
	keys := []string{}
	encodedIdentifier := state.EncodeIdentifier(identifier)
	it := txn.NewIterator(badger.DefaultIteratorOptions)
	prefix := fmt.Sprintf("%s-store", encodedIdentifier)
	defer it.Close()
	for it.Seek([]byte(prefix)); it.ValidForPrefix([]byte(prefix)); it.Next() {
		item := it.Item()
		wholeKey := item.Key()
		encodedKey := strings.Split(string(wholeKey), "-")[2]
		decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
		if err != nil {
			log.Warn().Msgf("Invalid key found for %s with key %v. Could not decode.", identifier, wholeKey)
			continue
		}
		keys = append(keys, string(decodedKey))
	}
	return keys
}

func fullKey(identifier string, key string) string {
	encodedIdentifier := state.EncodeIdentifier(identifier)
	encodedKey := base64.StdEncoding.EncodeToString([]byte(key))
	return fmt.Sprintf("%s-store-%s", encodedIdentifier, encodedKey)
}

func InsertKeyValueForIdentifier(s *state.State, config Config, identifier string, key string, value []byte) (string, error) {
	fullKey := fullKey(identifier, key)
	if config.StorageOptions.MaxValueSizeBytes > 0 && len(value) > int(config.StorageOptions.MaxValueSizeBytes) {
		return "", &ErrDataTooBig{}
	}
	err := s.DB.Update(func(txn *badger.Txn) error {
		currentKeys := keysForIdentifier(identifier, txn)
		if config.StorageOptions.MaxKeysPerAccount > 0 && uint64(len(currentKeys)) >= config.StorageOptions.MaxKeysPerAccount {
			return &ErrKeyLimitReached{}
		}
		e := badger.NewEntry([]byte(fullKey), value)
		return txn.SetEntry(e)
	})
	return fullKey, err
}

func KeysForIdentifier(s *state.State, identifier string) ([]string, error) {
	var keys *([]string) = nil
	err := s.DB.View(func(txn *badger.Txn) error {
		result := keysForIdentifier(identifier, txn)
		keys = &result
		return nil
	})
	return *keys, err
}

func RetrieveValueIdentifierAndKey(s *state.State, identifier string, key string) ([]byte, error) {
	fullKey := fullKey(identifier, key)
	value := []byte{}
	err := s.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(fullKey))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return &ErrKeyNotFound{}
			}
			return err
		}
		item.Value(func(v []byte) error {
			value = append([]byte{}, v...)
			return nil
		})
		return nil
	})
	return value, err
}

func DeleteKeyValueForIdentifier(s *state.State, identifier string, key string) error {
	fullKey := fullKey(identifier, key)
	err := s.DB.Update(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(fullKey))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return &ErrKeyNotFound{}
			}
			return err
		}
		return txn.Delete([]byte(fullKey))
	})
	return err
}
