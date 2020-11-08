// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package log

import (
	"context"

	"github.com/coreos/go-systemd/journal"
	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func WithLog(ctx context.Context, debug bool) context.Context {
	var err error
	var logger *zap.Logger
	if debug {
		zapctx.LogLevel.SetLevel(zapcore.DebugLevel)
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		logger = zapctx.Default
	}
	return zapctx.WithLogger(ctx, logger)
}

func journalHook(e zapcore.Entry) error {
	msg := e.Message
	if e.Level != zapcore.InfoLevel {
		msg = msg + " " + e.Caller.String() + " " + e.Stack
	}
	if e.Stack != "" {
		msg = msg + " " + e.Stack
	}
	return errors.WithStack(journal.Send(msg, journalLevel(e.Level), map[string]string{}))
}

type journalCore struct {
	enc   zapcore.Encoder
	debug bool
}

func newJournalCore(debug bool) *journalCore {
	return &journalCore{
		enc:   zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		debug: debug,
	}
}

func (c *journalCore) Enabled(l zapcore.Level) bool {
	return c.debug || l > zapcore.DebugLevel
}

func (c *journalCore) With(f []zapcore.Field) zapcore.Core {
	enc := c.enc.Clone()
	for i := range f {
		f[i].AddTo(enc)
	}
	return &journalCore{
		enc:   enc,
		debug: c.debug,
	}
}

func (c *journalCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return ce.AddCore(e, c)
}

func (c *journalCore) Write(e zapcore.Entry, f []zapcore.Field) error {
	buf, err := c.enc.EncodeEntry(e, f)
	if err != nil {
		return err
	}
	buf.Free()
	msg := e.Message + " " + buf.String()
	if e.Level > zapcore.InfoLevel {
		msg = msg + " " + e.Caller.String()
	}
	if e.Stack != "" {
		msg = msg + " " + e.Stack
	}
	return journal.Send(msg, journalLevel(e.Level), map[string]string{})
}

func (c *journalCore) Sync() error {
	return nil
}

func journalLevel(l zapcore.Level) journal.Priority {
	switch l {
	case zapcore.DebugLevel:
		return journal.PriDebug
	case zapcore.InfoLevel:
		return journal.PriInfo
	case zapcore.WarnLevel:
		return journal.PriWarning
	case zapcore.ErrorLevel:
		return journal.PriErr
	case zapcore.DPanicLevel:
		return journal.PriCrit
	case zapcore.PanicLevel:
		return journal.PriAlert
	case zapcore.FatalLevel:
		return journal.PriEmerg
	}
	return journal.PriInfo
}
