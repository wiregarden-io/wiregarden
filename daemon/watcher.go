// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/cenkalti/backoff"
	"github.com/go-chi/chi"
	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/wiregarden-io/wiregarden/agent"
	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/log"
)

type Watcher struct {
	server *http.Server

	wg       sync.WaitGroup
	mu       sync.Mutex
	agent    *agent.Agent
	watchers map[int64]func()
}

func New(a *agent.Agent) *Watcher {
	return &Watcher{agent: a, watchers: map[int64]func(){}}
}

func (d *Watcher) Start(ctx context.Context) error {
	zapctx.Debug(ctx, "watcher starting")
	d.mu.Lock()
	defer d.mu.Unlock()

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(zapctx.WithLogger(r.Context(), zapctx.Default)))
		})
	})
	r.Put("/watch/{id}", d.ensureWatch)
	r.Delete("/watch/{id}", d.deleteWatch)

	d.server = &http.Server{
		Handler: r,
	}

	if _, err := os.Stat(agent.WatcherSockPath()); err == nil {
		err = os.Remove(agent.WatcherSockPath())
		if err != nil {
			return errors.Wrap(err, "failed to clean up socket")
		}
	}
	l, err := net.Listen("unix", agent.WatcherSockPath())
	if err != nil {
		return errors.Wrap(err, "failed to open daemon socket")
	}
	go d.server.Serve(l)

	ifaces, err := d.agent.Interfaces()
	if err != nil {
		return errors.Wrap(err, "failed to get interfaces")
	}
	for i := range ifaces {
		wCtx, wCancel := context.WithCancel(ctx)
		go d.watchInterfaceEvents(wCtx, wCancel, &ifaces[i].Interface)
		d.watchers[ifaces[i].Id] = wCancel
	}

	zapctx.Debug(ctx, "watcher started")
	return nil
}

func (d *Watcher) Stop(ctx context.Context) {
	d.mu.Lock()
	for _, cancel := range d.watchers {
		cancel()
	}
	d.watchers = map[int64]func(){}
	if d.server != nil {
		d.server.Close()
		d.server = nil
	}
	d.mu.Unlock()
	zapctx.Debug(ctx, "watcher stopped")
}

func (d *Watcher) Wait(ctx context.Context) bool {
	defer d.Stop(ctx)
	ch := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		return false
	}
}

func (d *Watcher) ensureWatch(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx := log.WithLog(r.Context(), true)
	idParam := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		zapctx.Debug(ctx, "bad id", zap.String("id", idParam), zap.Error(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	zapctx.Debug(ctx, "ensure watch", zap.Int64("id", id))
	if _, ok := d.watchers[id]; ok {
		zapctx.Debug(ctx, "already watching", zap.Int64("id", id))
		return
	}

	iface, err := d.agent.Interface(id)
	if err != nil {
		zapctx.Debug(ctx, "failed to look up interface", zap.Int64("id", id), zap.Error(err))
		if errors.Is(err, agent.ErrDeviceNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	wCtx, wCancel := context.WithCancel(context.Background())
	go d.watchInterfaceEvents(wCtx, wCancel, iface)
	d.watchers[id] = wCancel
	w.WriteHeader(http.StatusOK)
}

func (d *Watcher) deleteWatch(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx := log.WithLog(r.Context(), true)
	idParam := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		zapctx.Debug(ctx, "bad id", zap.String("id", idParam), zap.Error(err))
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	zapctx.Debug(ctx, "delete watch", zap.Int64("id", id))
	if cancel, ok := d.watchers[id]; ok {
		delete(d.watchers, id)
		cancel()
	}
	w.WriteHeader(http.StatusOK)
}

func (d *Watcher) watchInterfaceEvents(ctx context.Context, cancel func(), iface *store.Interface) {
	d.wg.Add(1)
	defer d.wg.Done()
	zapctx.Debug(ctx, "start watching interface", zap.Int64("id", iface.Id))
	defer zapctx.Debug(ctx, "stop watching interface", zap.Int64("id", iface.Id))
	err := backoff.Retry(func() error {
		cl := &http.Client{}
		req, err := http.NewRequest("GET", iface.ApiUrl+"/v1/network/events?stream="+iface.Network.Id, nil)
		if err != nil {
			zapctx.Error(ctx, "failed to create request", zap.Error(err))
			return backoff.Permanent(errors.WithStack(err))
		}
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Accept", "application/stream+json")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(iface.DeviceToken))
		resp, err := cl.Do(req)
		if err != nil {
			zapctx.Error(ctx, "request failed", zap.Error(err))
			return errors.WithStack(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			contents, _ := ioutil.ReadAll(resp.Body)
			zapctx.Error(ctx, "error response", zap.Int("code", resp.StatusCode), zap.String("contents", string(contents)))
			return errors.Errorf("error response from api, code=%d: %q", resp.StatusCode, contents)
		}
		dec := json.NewDecoder(resp.Body)
		for {
			var ev struct{}
			err := dec.Decode(&ev)
			if err != nil {
				// TODO: handle EOF?
				zapctx.Error(ctx, "decode event failed", zap.Error(err))
				return errors.WithStack(err)
			}

			zapctx.Debug(ctx, "received event", zap.Reflect("event", ev))
			iface, err = d.agent.RefreshDevice(ctx, iface.Device.Name, iface.Network.Name, "")
			if err != nil {
				if errors.Is(err, agent.ErrInterfaceStateInvalid) {
					zapctx.Info(ctx, "interface no longer refreshable", zap.Error(err))
					cancel()
					return backoff.Permanent(errors.WithStack(err))
				}
				zapctx.Warn(ctx, "refresh failed",
					zap.Error(err),
					zap.String("device", iface.Device.Name),
					zap.String("network", iface.Network.Name))
				return backoff.Permanent(errors.WithStack(err))
			}
			err = d.agent.ApplyInterfaceChanges(ctx, iface)
			if err != nil {
				return errors.WithStack(err)
			}
			zapctx.Info(ctx, "refreshed on api server change",
				zap.String("device", iface.Device.Name),
				zap.String("network", iface.Network.Name))
		}
	}, backoff.NewExponentialBackOff())
	zapctx.Error(ctx, "watcher error", zap.Error(err))
}
