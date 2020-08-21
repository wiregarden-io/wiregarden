// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package agent

type ErrorResponse struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}

type InterfaceUpRequest struct {
	Name     string `json:"name"`
	Network  string `json:"network"`
	Endpoint string `json:"endpoint,omitempty"`
}

func (r *InterfaceUpRequest) Valid() error {
	return nil
}

type InterfaceUpResponse struct {
}
