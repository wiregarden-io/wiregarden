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
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-chi/chi"
	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	"github.com/wiregarden-io/wiregarden/agent"
	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/log"
)

type Watcher struct {
	server *http.Server

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
		if ifaces[i].Log.State == store.StateInterfaceDown {
			continue
		}
		err := d.agent.EnsureInterfaceState(&ifaces[i].Interface, &ifaces[i].Log)
		if err != nil {
			zapctx.Error(ctx, "failed to ensure interface state",
				zap.String("interface", ifaces[i].Interface.Name()), zap.Error(err))
		}
		wCtx, wCancel := context.WithCancel(ctx)
		go d.watchInterfaceEvents(wCtx, wCancel, &ifaces[i].Interface)
		d.watchers[ifaces[i].Id] = wCancel
	}

	go d.watchAddressChanges(ctx, func(ctx context.Context, update netlink.AddrUpdate, updatedLink netlink.Link) {
		ctx = zapctx.WithFields(ctx, zap.Reflect("update", update))
		if updatedLink == nil {
			// Ignore changes where we fail to look up the link by index. This
			// seems to happen when a link is removed.
			zapctx.Debug(ctx, "ignoring update without link information")
			return
		}
		linkAttrs := updatedLink.Attrs()
		ctx = zapctx.WithFields(ctx, zap.String("type", updatedLink.Type()))
		if updatedLink.Type() == "wireguard" {
			zapctx.Debug(ctx, "ignoring wireguard address change", zap.Reflect("attrs", linkAttrs))
			return
		}
		if update.LinkAddress.IP.To4() == nil {
			// TODO: for some reason, the IPv6 address seems to "change" on the
			// host interface without much reason. wiregarden doesn't support
			// IPv6 yet so we can just ignore these for now, but this needs
			// further investigation.
			zapctx.Debug(ctx, "ignoring IPv6 address change", zap.Reflect("attrs", linkAttrs))
			return
		}
		zapctx.Info(ctx, "network address change detected, exiting")
		os.Exit(1)
	})

	zapctx.Debug(ctx, "watcher started")
	return nil
}

func (d *Watcher) Shutdown(ctx context.Context) {
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

const initialReadTimeout = 15 * time.Second
const maxReadTimeout = 1 * time.Hour

func (d *Watcher) watchInterfaceEvents(ctx context.Context, cancel func(), iface *store.Interface) {
	zapctx.Debug(ctx, "start watching interface", zap.Int64("id", iface.Id))
	defer zapctx.Debug(ctx, "stop watching interface", zap.Int64("id", iface.Id))
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = 5 * time.Minute
	expBackoff.MaxElapsedTime = 0 // never stop retrying, until we hit a permanant error
	readTimeout := initialReadTimeout
	refreshAfter := time.Now().Add(readTimeout)
	err := backoff.Retry(func() error {
		cl := &http.Client{
			Transport: &http.Transport{
				IdleConnTimeout: readTimeout,
			},
		}
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
		refresh := func() error {
			ifaceNext, err := d.agent.RefreshDevice(ctx, agent.JoinArgs{Name: iface.Device.Name, Network: iface.Network.Name})
			if err != nil {
				if errors.Is(err, agent.ErrInterfaceStateChanging) {
					// Stale transaction is retryable
					return errors.WithStack(err)
				}
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
			err = d.agent.ApplyInterfaceChanges(ctx, ifaceNext)
			if err != nil {
				return errors.WithStack(err)
			}
			zapctx.Info(ctx, "refreshed on api server change",
				zap.String("device", ifaceNext.Device.Name),
				zap.String("network", ifaceNext.Network.Name))
			expBackoff.Reset()
			return nil
		}
		for {
			var ev struct{}
			err := dec.Decode(&ev)
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					if time.Now().After(refreshAfter) {
						readTimeout *= 2
						if readTimeout > maxReadTimeout {
							readTimeout = maxReadTimeout
						}
						refreshAfter = time.Now().Add(readTimeout)
						zapctx.Debug(ctx, "EOF", zap.Time("next_refresh", refreshAfter))
						if err := refresh(); err != nil {
							// Return any errors refreshing (which might exit the backoff retry)
							return err
						}
					}
					// Otherwise return the EOF (retriable)
					return err
				}
				zapctx.Error(ctx, "decode event failed", zap.Error(err))
				return errors.WithStack(err)
			}

			err = func() error {
				// Hold the mutex so that only one interface is updated at a
				// time, and we don't exit during a network interface change.
				d.mu.Lock()
				defer d.mu.Unlock()
				zapctx.Debug(ctx, "received event", zap.Reflect("event", ev))
				return refresh()
			}()
			if err != nil {
				return err
			}
			// Reset the read timeout
			readTimeout = initialReadTimeout
		}
	}, expBackoff)
	zapctx.Error(ctx, "watcher error", zap.Error(err))
}

type AddressChangeFunc func(context.Context, netlink.AddrUpdate, netlink.Link)

func (d *Watcher) watchAddressChanges(ctx context.Context, f AddressChangeFunc) error {
	updateCh := make(chan netlink.AddrUpdate)
	doneCh := make(chan struct{})
	err := netlink.AddrSubscribe(updateCh, doneCh)
	if err != nil {
		return errors.Wrap(err, "failed to subscribe to netlink changes")
	}
	for {
		select {
		case update := <-updateCh:
			var updatedLink netlink.Link
			if update.NewAddr {
				updatedLink, err = netlink.LinkByIndex(update.LinkIndex)
				if err != nil {
					zapctx.Error(ctx, "failed to lookup link",
						zap.Int("index", update.LinkIndex), zap.Error(err))
				}
			}
			d.mu.Lock()
			f(ctx, update, updatedLink)
			d.mu.Unlock()
		case <-ctx.Done():
			close(doneCh)
		}
	}
}
