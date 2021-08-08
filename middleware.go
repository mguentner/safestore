package main

import (
	"net/http"

	"github.com/mguentner/passwordless/state"
	"github.com/rs/zerolog/log"
)

func GetStateAndConfig(w http.ResponseWriter, r *http.Request) (*state.State, *Config, bool) {
	state := r.Context().Value("state").(*state.State)
	config := r.Context().Value("config").(*Config)
	if state == nil {
		log.Error().Msg("Setup error: No state in context")
		return nil, nil, false
	}
	if config == nil {
		log.Error().Msg("Setup error: No config in context")
		return nil, nil, false
	}
	return state, config, true
}
