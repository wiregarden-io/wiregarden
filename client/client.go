// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/wiregarden-io/wiregarden/types"
)

const (
	defaultApiUrl = "https://wiregarden.io/api"
)

type Client struct {
	*http.Client

	apiUrl string
}

var (
	ErrDeviceAlreadyJoined = errors.New("device already joined")
)

func New(apiUrl string) *Client {
	if apiUrl == "" {
		apiUrl = defaultApiUrl
	}
	return &Client{
		Client: http.DefaultClient,
		apiUrl: apiUrl,
	}
}

func (c *Client) Request(ctx context.Context, method, url string, v interface{}) (*http.Response, error) {
	var reqContents io.Reader
	if v != nil {
		buf, err := json.Marshal(v)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal request")
		}
		reqContents = bytes.NewBuffer(buf)
	}
	req, err := http.NewRequest(method, c.apiUrl+url, reqContents)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	if token := ctx.Value("token").([]byte); token != nil {
		req.Header.Set("authorization",
			"Bearer "+base64.StdEncoding.EncodeToString(token))
	}
	return c.Do(req)
}

func (c *Client) Response(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respContents, _ := ioutil.ReadAll(resp.Body)
		return errors.Errorf("request failed: HTTP %d: %s", resp.StatusCode, string(respContents))
	}
	if v == nil {
		return nil
	}

	err := json.NewDecoder(resp.Body).Decode(v)
	if err != nil {
		return errors.Wrap(err, "failed to decode server response")
	}
	return nil
}

func (c *Client) JoinDevice(ctx context.Context, joinReq *types.JoinDeviceRequest) (*types.JoinDeviceResponse, error) {
	resp, err := c.Request(ctx, "POST", "/v1/device", &joinReq)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, errors.WithStack(ErrDeviceAlreadyJoined)
	}
	var joinResp types.JoinDeviceResponse
	err = c.Response(resp, &joinResp)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &joinResp, nil
}

func (c *Client) RefreshDevice(ctx context.Context, refreshReq *types.RefreshDeviceRequest) (*types.JoinDeviceResponse, error) {
	resp, err := c.Request(ctx, "PUT", "/v1/device", refreshReq)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	var joinResp types.JoinDeviceResponse
	err = c.Response(resp, &joinResp)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &joinResp, nil
}

func (c *Client) DepartDevice(ctx context.Context) error {
	resp, err := c.Request(ctx, "DELETE", "/v1/device", nil)
	if err != nil {
		return errors.Wrap(err, "request failed")
	}
	err = c.Response(resp, nil)
	if err != nil {
		return errors.Wrap(err, "failed to depart device")
	}
	return nil
}

func (c *Client) Whoami(ctx context.Context) (string, error) {
	resp, err := c.Request(ctx, "GET", "/admin/whoami", nil)
	if err != nil {
		return "", errors.Wrap(err, "request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("request failed, HTTP %d", resp.StatusCode)
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to read response")
	}
	return strings.TrimSpace(string(buf)), nil
}

var ErrNotFound = errors.Errorf("not found")

func (c *Client) GetSubscriptionToken(ctx context.Context, plan string) (*types.GetSubscriptionTokenResponse, error) {
	resp, err := c.Request(ctx, "PUT", "/v1/subscription/"+plan+"/token", nil)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	var subTokenResp types.GetSubscriptionTokenResponse
	err = c.Response(resp, &subTokenResp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}
	return &subTokenResp, nil
}
