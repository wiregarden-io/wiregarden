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
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/juju/zaputil/zapctx"
	"github.com/wiregarden-io/wiregarden/agent/store"
	"go.uber.org/zap"
)

func WatcherLockPath() string {
	return runDir() + "/.wiregarden.watcher.lock"
}

func WatcherSockPath() string {
	return runDir() + "/.wiregarden.watcher.sock"
}

func runDir() string {
	if snapData := os.Getenv("SNAP_DATA"); snapData != "" {
		return snapData
	}
	return "/var/run"
}

type watcherClient struct {
	http.Client
}

func newWatcherClient() *watcherClient {
	return &watcherClient{
		http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					dialer := net.Dialer{}
					return dialer.DialContext(ctx, "unix", WatcherSockPath())
				},
			},
		},
	}
}

func (c *watcherClient) applyState(ctx context.Context, id int64, state store.State) {
	switch state {
	case store.StateInterfaceUp:
		c.ensureWatch(ctx, id)
	case store.StateInterfaceDown:
		c.deleteWatch(ctx, id)
	}
}

func (c *watcherClient) ensureWatch(ctx context.Context, id int64) {
	if c == nil {
		return
	}
	req, err := http.NewRequest("PUT", fmt.Sprintf("http://unix/watch/%d", id), nil)
	if err != nil {
		zapctx.Error(ctx, "request failed", zap.Error(err), zap.Int64("id", id))
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		zapctx.Error(ctx, "request failed", zap.Error(err), zap.Int64("id", id))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		zapctx.Error(ctx, "bad response", zap.Int("code", resp.StatusCode))
		return
	}
}

func (c *watcherClient) deleteWatch(ctx context.Context, id int64) {
	if c == nil {
		return
	}
	req, err := http.NewRequest("DELETE", fmt.Sprintf("http://unix/watch/%d", id), nil)
	if err != nil {
		zapctx.Error(ctx, "request failed", zap.Error(err), zap.Int64("id", id))
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		zapctx.Error(ctx, "request failed", zap.Error(err), zap.Int64("id", id))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		zapctx.Error(ctx, "bad response", zap.Int("code", resp.StatusCode))
		return
	}
}
