package main

import (
	"bytes"
	"testing"

	"github.com/dgraph-io/badger/v3"
	"github.com/mguentner/passwordless/state"
)

func TestInsertionNoLimits(t *testing.T) {
	config := DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	appState := state.State{
		DB: db,
	}
	insertedKey, err := InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "needle", []byte("value"))
	if err != nil {
		t.Fatalf("Unexpected failure: %v", err)
	}
	if len(insertedKey) == 0 {
		t.Fatal("Expected non-empty key")
	}
	keys, err := KeysForIdentifier(&appState, "alice@example.com")
	if err != nil {
		t.Fatalf("Unexpected failure: %v", err)
	}
	if len(keys) != 1 {
		t.Fatal("Expected one key")
	}
	if keys[0] != "needle" {
		t.Fatalf("Expected %s, got %s", "needle", keys[0])
	}
	insertedKey2, err := InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "needle1", []byte("value"))
	if err != nil {
		t.Fatalf("Unexpected failure: %v", err)
	}
	if len(insertedKey2) == 0 {
		t.Fatal("Expected non-empty key")
	}
	keys, err = KeysForIdentifier(&appState, "alice@example.com")
	if err != nil {
		t.Fatalf("Unexpected failure: %v", err)
	}
	if len(keys) != 2 {
		t.Fatal("Expected one key")
	}
}

func TestInsertionLimits(t *testing.T) {
	config := DefaultConfig()
	config.StorageOptions.MaxKeysPerAccount = 2
	config.StorageOptions.MaxValueSizeBytes = 10
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	appState := state.State{
		DB: db,
	}
	_, err = InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "1", []byte("value"))
	if err != nil {
		t.Fatalf("Unexpected failure: %v", err)
	}
	_, err = InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "2", []byte("longerthan10bytes"))
	if err == nil {
		t.Fatalf("Expected error: %v", err)
	}
	if _, ok := err.(*ErrDataTooBig); !ok {
		t.Fatalf("Expected ErrDataTooBig")
	}
	_, err = InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "2", []byte("value"))
	if err != nil {
		t.Fatalf("Unexpected failure: %v", err)
	}
	_, err = InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "3", []byte("value"))
	if err == nil {
		t.Fatalf("Expected error")
	}
	if _, ok := err.(*ErrKeyLimitReached); !ok {
		t.Fatalf("Expected ErrKeyLimitReached")
	}
}

func TestRetrieve(t *testing.T) {
	config := DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	appState := state.State{
		DB: db,
	}
	value, err := RetrieveValueIdentifierAndKey(&appState, "alice@example.com", "needle")
	if err == nil {
		t.Fatal("Expected an error")
	}
	if bytes.Compare(value, []byte{}) != 0 {
		t.Fatal("Expected an empty slice")
	}
	_, err = InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "needle", []byte("value"))
	if err != nil {
		t.Fatalf("Unexpected failure: %v", err)
	}
	value, err = RetrieveValueIdentifierAndKey(&appState, "alice@example.com", "needle")
	if err != nil {
		t.Fatal("Expected no error")
	}
	if bytes.Compare(value, []byte("value")) != 0 {
		t.Fatal("Expected an empty slice")
	}
}

func TestDelete(t *testing.T) {
	config := DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	appState := state.State{
		DB: db,
	}
	err = DeleteKeyValueForIdentifier(&appState, "alice@example.com", "needle")
	if err == nil {
		t.Fatal("Expected an error")
	}
	InsertKeyValueForIdentifier(&appState, config, "alice@example.com", "needle", []byte("value"))
	err = DeleteKeyValueForIdentifier(&appState, "alice@example.com", "needle")
	if err != nil {
		t.Fatal("Unexpected error")
	}
}
