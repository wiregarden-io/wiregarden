// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

// Package api provides for communication with the wiregarden.io API.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
)

const (
	DefaultApiUrl = "https://wiregarden.io/api"
)

type Client struct {
	*http.Client

	apiUrl string
}

var (
	ErrApiServer           = fmt.Errorf("api server error")
	ErrApiClient           = fmt.Errorf("api client error")
	ErrApiForbidden        = fmt.Errorf("api client forbidden")
	ErrApiRevoked          = fmt.Errorf("api client revoked")
	ErrApiInvalidResponse  = fmt.Errorf("api server gave an invalid response")
	ErrDeviceAlreadyJoined = errors.Wrap(ErrApiClient, "device already joined")
)

func RetryableError(err error) error {
	if errors.Is(err, ErrApiClient) {
		return backoff.Permanent(err)
	}
	return err
}

func New(apiUrl string) *Client {
	if apiUrl == "" {
		apiUrl = DefaultApiUrl
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Not a 2xx OK response...
		respContents, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			// It's not me it's you
			return errors.Wrapf(ErrApiServer, "request failed: HTTP %d: %s", resp.StatusCode, string(respContents))
		} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// It's not you it's me
			if resp.StatusCode == 403 {
				return errors.Wrapf(ErrApiForbidden, "request failed: HTTP %d: %s", resp.StatusCode, string(respContents))
			} else if resp.StatusCode == 410 {
				return errors.Wrapf(ErrApiRevoked, "request failed: HTTP %d: %s", resp.StatusCode, string(respContents))
			} else {
				return errors.Wrapf(ErrApiClient, "request failed: HTTP %d: %s", resp.StatusCode, string(respContents))
			}
		} else {
			// Unexpected response codes indicate a misconfigured frontend
			// reverse proxy or worse. Currently the API does not do 1xx or 3xx
			// response codes, so this is unexpected.
			return errors.Wrapf(ErrApiInvalidResponse, "request failed: HTTP %d: %s", resp.StatusCode, string(respContents))
		}
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

func (c *Client) JoinDevice(ctx context.Context, joinReq *JoinDeviceRequest) (*JoinDeviceResponse, error) {
	resp, err := c.Request(ctx, "POST", "/v1/device", &joinReq)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	if resp.StatusCode == http.StatusConflict {
		// TODO: need to make this idempotent because we don't have the device
		// token if we need to retry...
		return nil, errors.WithStack(ErrDeviceAlreadyJoined)
	}
	var joinResp JoinDeviceResponse
	err = c.Response(resp, &joinResp)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &joinResp, nil
}

func (c *Client) RefreshDevice(ctx context.Context, refreshReq *RefreshDeviceRequest) (*JoinDeviceResponse, error) {
	resp, err := c.Request(ctx, "PUT", "/v1/device", refreshReq)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	var joinResp JoinDeviceResponse
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

func (c *Client) ListDevices(ctx context.Context) (*ListDevicesResponse, error) {
	resp, err := c.Request(ctx, "GET", "/v1/device", nil)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("request failed, HTTP %d", resp.StatusCode)
	}
	var listResp ListDevicesResponse
	err = c.Response(resp, &listResp)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &listResp, nil
}

func (c *Client) DeleteDevice(ctx context.Context, deviceId string) error {
	resp, err := c.Request(ctx, "DELETE", "/v1/device/"+deviceId, nil)
	if err != nil {
		return errors.Wrap(err, "request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("request failed, HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) DeleteNetwork(ctx context.Context, networkId string) error {
	resp, err := c.Request(ctx, "DELETE", "/v1/network/"+networkId, nil)
	if err != nil {
		return errors.Wrap(err, "request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("request failed, HTTP %d", resp.StatusCode)
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

func (c *Client) GetSubscriptionToken(ctx context.Context, plan string) (*GetSubscriptionTokenResponse, error) {
	resp, err := c.Request(ctx, "PUT", "/v1/subscription/"+plan+"/token", nil)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	var subTokenResp GetSubscriptionTokenResponse
	err = c.Response(resp, &subTokenResp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}
	return &subTokenResp, nil
}

func (c *Client) ListSubscriptions(ctx context.Context) (*ListSubscriptionsResponse, error) {
	resp, err := c.Request(ctx, "GET", "/v1/subscription", nil)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	var listSubsResp ListSubscriptionsResponse
	err = c.Response(resp, &listSubsResp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode response")
	}
	return &listSubsResp, nil
}
