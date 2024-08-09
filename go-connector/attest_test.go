/*
 *   Copyright (c) 2022-2023 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package connector

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

type MockAdapter struct {
	mock.Mock
}

func (mock MockAdapter) CollectEvidence(nonce []byte) (*Evidence, error) {
	args := mock.Called(nonce)
	return args.Get(0).(*Evidence), args.Error(1)
}

func TestAttest(t *testing.T) {
	connector, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc(nonceEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"val":"` + nonceVal + `","iat":"` + nonceIat + `","signature":"` + nonceSig + `"}`))
	})

	adapter := MockAdapter{}
	evidence := &Evidence{}
	adapter.On("CollectEvidence", mock.Anything).Return(evidence, nil)

	mux.HandleFunc(attestEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + token + `"}`))
	})

	_, err := connector.Attest(AttestArgs{adapter, nil, "req1", "", false})
	if err != nil {
		t.Errorf("Attest returned unexpcted error: %v", err)
	}
}

func TestAttest_nonceFailure(t *testing.T) {
	connector, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc(nonceEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid nonce`))
	})

	adapter := MockAdapter{}
	adapter.On("CollectEvidence", mock.Anything).Return(mock.Anything, nil)

	mux.HandleFunc(attestEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + token + `"}`))
	})

	_, err := connector.Attest(AttestArgs{adapter, nil, "req1", string(PS384), false})
	if err == nil {
		t.Errorf("Attest returned nil, expected error")
	}
}

func TestAttest_evidenceFailure(t *testing.T) {
	connector, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc(nonceEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"val":"` + nonceVal + `","iat":"` + nonceIat + `","signature":"` + nonceSig + `"}`))
	})

	adapter := MockAdapter{}
	evidence := &Evidence{}
	adapter.On("CollectEvidence", mock.Anything).Return(evidence, errors.New("failed to collect evidence"))

	mux.HandleFunc(attestEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + token + `"}`))
	})

	_, err := connector.Attest(AttestArgs{adapter, nil, "req1", string(RS256), false})
	if err == nil {
		t.Errorf("Attest returned nil, expected error")
	}
}

func TestAttest_tokenFailure(t *testing.T) {
	connector, mux, _, teardown := setup()
	defer teardown()

	mux.HandleFunc(nonceEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"val":"` + nonceVal + `","iat":"` + nonceIat + `","signature":"` + nonceSig + `"}`))
	})

	adapter := MockAdapter{}
	evidence := &Evidence{}
	adapter.On("CollectEvidence", mock.Anything).Return(evidence, nil)

	mux.HandleFunc(attestEndpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid token`))
	})

	_, err := connector.Attest(AttestArgs{adapter, nil, "req1", "", false})
	if err == nil {
		t.Errorf("Attest returned nil, expected error")
	}
}
