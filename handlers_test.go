package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"
	"github.com/mguentner/passwordless/crypto"
	"github.com/mguentner/passwordless/middleware"
	"github.com/mguentner/passwordless/state"
)

func TestAccessTokenFail(t *testing.T) {
	config := DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	appState := state.State{
		DB: db,
	}
	requests := []struct {
		route   string
		method  string
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{
			route:   "/api/store",
			method:  "GET",
			handler: IndexHandler,
		},
		{
			route:   "/api/store/key",
			method:  "GET",
			handler: RetrieveHandler,
		},
		{
			route:   "/api/store/key",
			method:  "POST",
			handler: InsertHandler,
		},
		{
			route:   "/api/store/key",
			method:  "DELETE",
			handler: DeleteHandler,
		},
	}

	for _, request := range requests {
		req, err := http.NewRequest(request.method, request.route, nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler := http.HandlerFunc(request.handler)
		ctxHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), "state", &appState)
			ctx = context.WithValue(ctx, "config", &config)
			handler.ServeHTTP(w, r.WithContext(ctx))
		})
		ctxHandler.ServeHTTP(recorder, req)
		status := recorder.Code
		if status != http.StatusUnauthorized {
			t.Errorf("Expected StatusUnauthorized for %s on %s", request.method, request.route)
		}
	}
}

func TestHandlerUnauthorized(t *testing.T) {
	config := DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	appState := state.State{
		DB: db,
	}
	requests := []struct {
		route  string
		method string
	}{
		{
			route:  "/api/store",
			method: "GET",
		},
		{
			route:  "/api/store/key",
			method: "GET",
		},
		{
			route:  "/api/store/key",
			method: "POST",
		},
		{
			route:  "/api/store/key",
			method: "DELETE",
		},
	}
	handler := SetupHandler(&config, &appState)
	for _, request := range requests {
		req, err := http.NewRequest(request.method, request.route, nil)
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		status := recorder.Code
		if status != http.StatusUnauthorized {
			t.Errorf("Expected StatusUnauthorized for %s on %s", request.method, request.route)
		}
	}
}

func setupHandlerTest(t *testing.T, route string, handler http.HandlerFunc) (*Config, state.State, []crypto.PublicPrivateRSAKeyPair, http.HandlerFunc) {
	config := DefaultConfig()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatal(err)
	}
	keyPairs := crypto.KeyPairForTesting()
	appState := state.State{
		DB:          db,
		RSAKeyPairs: keyPairs,
	}
	router := mux.NewRouter()
	router.Use(middleware.WithJWTHandler)
	router.HandleFunc(route, handler)
	ctxHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "state", &appState)
		ctx = context.WithValue(ctx, "config", &config)
		router.ServeHTTP(w, r.WithContext(ctx))
	})
	return &config, appState, keyPairs, ctxHandler
}

func TestInsertHandler(t *testing.T) {
	config, appState, keyPairs, handler := setupHandlerTest(t, "/store/{key}", InsertHandler)
	accessToken, err := crypto.CreateAccessToken(*config.GetConfig(), keyPairs, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	content := "content"
	reader := strings.NewReader(content)
	req, err := http.NewRequest("POST", "/store/foo", reader)
	if err != nil {
		t.Fatal(err)
	}
	authHeader := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Set("Authorization", authHeader)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	status := recorder.Code
	if status != http.StatusCreated {
		t.Errorf("Expected StatusCreated, got %d", status)
	}
	value, err := RetrieveValueIdentifierAndKey(&appState, "alice@example.com", "foo")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare([]byte(content), value) != 0 {
		t.Fatalf("Expected stored value to be %s", content)
	}
}

func TestInsertHandlerLimits(t *testing.T) {
	config, _, keyPairs, handler := setupHandlerTest(t, "/store/{key}", InsertHandler)
	config.StorageOptions.MaxKeysPerAccount = 2
	config.StorageOptions.MaxValueSizeBytes = 10
	accessToken, err := crypto.CreateAccessToken(*config.GetConfig(), keyPairs, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	contentTooLong := "thiscontentislongerthantenbytes"
	content := "content"
	reader := strings.NewReader(content)
	tooLongReader := strings.NewReader(contentTooLong)
	{
		req, err := http.NewRequest("POST", "/store/1", reader)
		if err != nil {
			t.Fatal(err)
		}
		authHeader := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Set("Authorization", authHeader)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		status := recorder.Code
		if status != http.StatusCreated {
			t.Errorf("Expected StatusCreated, got %d", status)
		}
	}
	{
		req, err := http.NewRequest("POST", "/store/2", tooLongReader)
		if err != nil {
			t.Fatal(err)
		}
		authHeader := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Set("Authorization", authHeader)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		status := recorder.Code
		if status != http.StatusRequestEntityTooLarge {
			t.Errorf("Expected StatusRequestEntityTooLarge, got %d", status)
		}
	}
	{
		req, err := http.NewRequest("POST", "/store/2", reader)
		if err != nil {
			t.Fatal(err)
		}
		authHeader := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Set("Authorization", authHeader)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		status := recorder.Code
		if status != http.StatusCreated {
			t.Errorf("Expected StatusCreated, got %d", status)
		}
	}
	{
		req, err := http.NewRequest("POST", "/store/3", reader)
		if err != nil {
			t.Fatal(err)
		}
		authHeader := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Set("Authorization", authHeader)

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		status := recorder.Code
		if status != http.StatusPreconditionFailed {
			t.Errorf("Expected StatusPreconditionFailed, got %d", status)
		}
	}
}

func TestRetrieveHandler(t *testing.T) {
	config, appState, keyPairs, handler := setupHandlerTest(t, "/store/{key}", RetrieveHandler)
	accessToken, err := crypto.CreateAccessToken(*config.GetConfig(), keyPairs, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/store/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	authHeader := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Set("Authorization", authHeader)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	status := recorder.Code
	if status != http.StatusNotFound {
		t.Errorf("Expected NotFound, got %d", status)
	}
	content := "content"
	_, err = InsertKeyValueForIdentifier(&appState, *config, "alice@example.com", "foo", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	req2, err := http.NewRequest("GET", "/store/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", authHeader)

	recorder2 := httptest.NewRecorder()
	handler.ServeHTTP(recorder2, req2)
	status2 := recorder2.Code
	if status2 != http.StatusOK {
		t.Errorf("Expected OK, got %d", status)
	}

}

func TestIndexHandler(t *testing.T) {
	config, appState, keyPairs, handler := setupHandlerTest(t, "/store", IndexHandler)
	accessToken, err := crypto.CreateAccessToken(*config.GetConfig(), keyPairs, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/store", nil)
	if err != nil {
		t.Fatal(err)
	}
	authHeader := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Set("Authorization", authHeader)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	status := recorder.Code
	if status != http.StatusOK {
		t.Errorf("Expected OK, got %d", status)
	}
	var result IndexReponse
	decoder := json.NewDecoder(recorder.Body)
	err = decoder.Decode(&result)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Keys) != 0 {
		t.Error("Expected result to be empty")
	}

	content := "content"
	_, err = InsertKeyValueForIdentifier(&appState, *config, "alice@example.com", "foo", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	req2, err := http.NewRequest("GET", "/store", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", authHeader)

	recorder2 := httptest.NewRecorder()
	handler.ServeHTTP(recorder2, req2)
	status2 := recorder2.Code
	if status2 != http.StatusOK {
		t.Errorf("Expected OK, got %d", status)
	}
	var result2 IndexReponse
	decoder2 := json.NewDecoder(recorder2.Body)
	err = decoder2.Decode(&result2)
	if err != nil {
		t.Fatal(err)
	}
	if len(result2.Keys) != 1 {
		t.Error("Expected result to have one element")
	}
}

func TestDeleteHandler(t *testing.T) {
	config, appState, keyPairs, handler := setupHandlerTest(t, "/store/{key}", DeleteHandler)
	accessToken, err := crypto.CreateAccessToken(*config.GetConfig(), keyPairs, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("DELETE", "/store/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	authHeader := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Set("Authorization", authHeader)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	status := recorder.Code
	if status != http.StatusNotFound {
		t.Errorf("Expected NotFound, got %d", status)
	}
	content := "content"
	_, err = InsertKeyValueForIdentifier(&appState, *config, "alice@example.com", "foo", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	req2, err := http.NewRequest("DELETE", "/store/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", authHeader)

	recorder2 := httptest.NewRecorder()
	handler.ServeHTTP(recorder2, req2)
	status2 := recorder2.Code
	if status2 != http.StatusOK {
		t.Errorf("Expected OK, got %d", status)
	}
	keys, err := KeysForIdentifier(&appState, "alice@example.com")
	if len(keys) != 0 {
		t.Error("Key still in database")
	}
}
