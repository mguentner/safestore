package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mguentner/passwordless/crypto"
	"github.com/mguentner/passwordless/middleware"
	"github.com/rs/zerolog/log"
)

func extractKey(r *http.Request) (string, error) {
	vars := mux.Vars(r)
	key, ok := vars["key"]
	if !ok {
		return "", errors.New("NoKeyFoundInRequest")
	}
	return key, nil
}

func InsertHandler(w http.ResponseWriter, r *http.Request) {
	state, config, ok := GetStateAndConfig(w, r)
	if !ok {
		return
	}
	accessToken, ok := r.Context().Value("accessToken").(*crypto.DefaultClaims)
	if !ok || accessToken == nil {
		middleware.HttpJSONError(w, "NoAccessTokenFound", http.StatusUnauthorized)
		return
	}
	key, err := extractKey(r)
	if err != nil {
		middleware.HttpJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(r.Body)
	if err != nil {
		log.Error().Msg("Could not read from request")
		middleware.HttpJSONError(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	_, err = InsertKeyValueForIdentifier(state, *config, accessToken.Identifier, key, buf.Bytes())
	if err != nil {
		if _, ok := err.(*ErrKeyLimitReached); ok {
			middleware.HttpJSONError(w, "KeyLimitReached", http.StatusPreconditionFailed)
			return
		}
		if _, ok := err.(*ErrDataTooBig); ok {
			middleware.HttpJSONError(w, "PayloadTooLarge", http.StatusRequestEntityTooLarge)
			return
		}
		log.Error().Msgf("Operation error: %s", err.Error())
		middleware.HttpJSONError(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func RetrieveHandler(w http.ResponseWriter, r *http.Request) {
	state, _, ok := GetStateAndConfig(w, r)
	if !ok {
		return
	}
	accessToken, ok := r.Context().Value("accessToken").(*crypto.DefaultClaims)
	if !ok || accessToken == nil {
		middleware.HttpJSONError(w, "NoAccessTokenFound", http.StatusUnauthorized)
		return
	}
	key, err := extractKey(r)
	if err != nil {
		middleware.HttpJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	value, err := RetrieveValueIdentifierAndKey(state, accessToken.Identifier, key)
	if err != nil {
		if _, ok := err.(*ErrKeyNotFound); ok {
			middleware.HttpJSONError(w, "KeyNotFound", http.StatusNotFound)
			return
		}
		log.Error().Msgf("Operation error: %s", err.Error())
		middleware.HttpJSONError(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	w.Write(value)
	w.Header().Set("Content-Type", "application/octet-stream")
}

func DeleteHandler(w http.ResponseWriter, r *http.Request) {
	state, _, ok := GetStateAndConfig(w, r)
	if !ok {
		return
	}
	accessToken, ok := r.Context().Value("accessToken").(*crypto.DefaultClaims)
	if !ok || accessToken == nil {
		middleware.HttpJSONError(w, "NoAccessTokenFound", http.StatusUnauthorized)
		return
	}
	key, err := extractKey(r)
	if err != nil {
		middleware.HttpJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = DeleteKeyValueForIdentifier(state, accessToken.Identifier, key)
	if err != nil {
		if _, ok := err.(*ErrKeyNotFound); ok {
			middleware.HttpJSONError(w, "KeyNotFound", http.StatusNotFound)
			return
		}
		log.Error().Msgf("Operation error: %s", err.Error())
		middleware.HttpJSONError(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
}

type IndexReponse struct {
	Keys []string `json:"keys"`
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	state, _, ok := GetStateAndConfig(w, r)
	if !ok {
		return
	}
	accessToken, ok := r.Context().Value("accessToken").(*crypto.DefaultClaims)
	if !ok || accessToken == nil {
		middleware.HttpJSONError(w, "NoAccessTokenFound", http.StatusUnauthorized)
		return
	}
	keys, err := KeysForIdentifier(state, accessToken.Identifier)
	if err != nil {
		log.Error().Msgf("Operation error: %s", err.Error())
		middleware.HttpJSONError(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	response := IndexReponse{
		Keys: keys,
	}
	encoder := json.NewEncoder(w)
	err = encoder.Encode(response)
	if err != nil {
		log.Error().Msgf("Encoder error: %s", err.Error())
		middleware.HttpJSONError(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	return
}
