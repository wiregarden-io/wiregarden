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
	"go.uber.org/zap"
)

func WatcherLockPath() string {
	return os.TempDir() + "/.wiregarden.watcher.lock"
}

func WatcherSockPath() string {
	return os.TempDir() + "/.wiregarden.watcher.sock"
}

type watcherClient struct {
	http.Client
}

func newWatcherClient() *watcherClient {
	return &watcherClient{
		http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", WatcherSockPath())
				},
			},
		},
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
