package slogsysloghandler

import (
	"log/slog"
	"log/syslog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	pDebug  syslog.Priority = syslog.LOG_DEBUG
	pInfo   syslog.Priority = syslog.LOG_INFO
	pWarn   syslog.Priority = syslog.LOG_WARNING
	pErr    syslog.Priority = syslog.LOG_ERR
	pCrit   syslog.Priority = syslog.LOG_CRIT
	pNotice syslog.Priority = syslog.LOG_NOTICE
)

type syslogWriterMock struct {
	mu           sync.Mutex
	lastMsg      *string
	lastSeverity *syslog.Priority
}

func (w *syslogWriterMock) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastMsg = nil
	w.lastSeverity = nil
}

func (w *syslogWriterMock) empty() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastMsg == nil || w.lastSeverity == nil
}

func (w *syslogWriterMock) Debug(msg string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastMsg = &msg
	w.lastSeverity = &pDebug
	return nil
}

func (w *syslogWriterMock) Info(msg string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastMsg = &msg
	w.lastSeverity = &pInfo
	return nil
}

func (w *syslogWriterMock) Notice(msg string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastMsg = &msg
	w.lastSeverity = &pNotice
	return nil
}

func (w *syslogWriterMock) Warning(msg string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastMsg = &msg
	w.lastSeverity = &pWarn
	return nil
}

func (w *syslogWriterMock) Err(msg string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastMsg = &msg
	w.lastSeverity = &pErr
	return nil
}

func (w *syslogWriterMock) Crit(msg string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastMsg = &msg
	w.lastSeverity = &pCrit
	return nil
}

func TestLowerLevelIgnored(t *testing.T) {
	w := &syslogWriterMock{}
	l := slog.New(NewSyslogHandler(w, false, &slog.HandlerOptions{Level: slog.LevelWarn}))
	l.Debug("debug")
	assert.True(t, w.empty(), "debug message should not be logged")
	w.reset()
	l.Info("info")
	assert.True(t, w.empty(), "info message should be not logged")
}

func TestUpperLevelNotIgnored(t *testing.T) {
	w := &syslogWriterMock{}
	l := slog.New(NewSyslogHandler(w, false, &slog.HandlerOptions{Level: slog.LevelWarn}))
	l.Warn("warn")
	assert.False(t, w.empty(), "warn message should be logged")
	w.reset()
	l.Error("err")
	assert.False(t, w.empty(), "err message should be logged")
}

func checkLast(t *testing.T, w *syslogWriterMock, severity syslog.Priority, msg string) {
	require.False(t, w.empty(), "message should be logged")
	assert.Equal(t, severity, *w.lastSeverity, "severity should be correct")
	assert.Equal(t, msg, *w.lastMsg, "message should be correct")
}

func TestTextMsgContent(t *testing.T) {
	w := &syslogWriterMock{}
	l := slog.New(NewSyslogHandler(w, false, &slog.HandlerOptions{Level: slog.LevelWarn}))
	l.Warn("foobar")
	checkLast(t, w, pWarn, "msg=foobar")
}
