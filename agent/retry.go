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

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"

	"github.com/wiregarden-io/wiregarden/api"
)

func newRetryClient(cl Client, newBackOff func() backoff.BackOff) Client {
	if newBackOff == nil {
		newBackOff = defaultRetryClientBackOff
	}
	return &retryClient{cl: cl, newBackOff: newBackOff}
}

func defaultRetryClientBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Second
	return b
}

type retryClient struct {
	cl         Client
	newBackOff func() backoff.BackOff
}

func (rc *retryClient) JoinDevice(ctx context.Context, req *api.JoinDeviceRequest) (*api.JoinDeviceResponse, error) {
	var resp *api.JoinDeviceResponse
	err := backoff.Retry(func() error {
		var err error
		resp, err = rc.cl.JoinDevice(ctx, req)
		if err != nil {
			return api.RetryableError(err)
		}
		return nil
	}, rc.newBackOff())
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (rc *retryClient) RefreshDevice(ctx context.Context, req *api.RefreshDeviceRequest) (*api.JoinDeviceResponse, error) {
	var resp *api.JoinDeviceResponse
	err := backoff.Retry(func() error {
		var err error
		resp, err = rc.cl.RefreshDevice(ctx, req)
		if err != nil {
			return api.RetryableError(err)
		}
		return nil
	}, rc.newBackOff())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return resp, nil
}

func (rc *retryClient) DepartDevice(ctx context.Context) error {
	return errors.WithStack(backoff.Retry(func() error {
		err := rc.cl.DepartDevice(ctx)
		if err != nil {
			return api.RetryableError(err)
		}
		return nil
	}, rc.newBackOff()))
}
