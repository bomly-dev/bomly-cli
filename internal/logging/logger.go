package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// NewConsole returns a logger configured for human-readable terminal output.
// verbosity controls the log level: 0 = warn, 1 = info, 2+ = debug.
// When quiet is true the logger only emits errors.
func NewConsole(stderr io.Writer, verbosity int, quiet bool) *zap.Logger {
	if stderr == nil {
		stderr = io.Discard
	}

	level := zap.NewAtomicLevelAt(zap.WarnLevel)
	if quiet {
		level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	} else if verbosity >= 2 {
		level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else if verbosity == 1 {
		level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	encoderCfg := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "level",
		NameKey:        "logger",
		TimeKey:        "",
		CallerKey:      "",
		FunctionKey:    "",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeName:     zapcore.FullNameEncoder,
		EncodeTime:     zapcore.EpochTimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	encoder := newPrettyConsoleEncoder(encoderCfg)
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(stderr),
		level,
	)

	return zap.New(core)
}

// FormatDuration returns a short human-readable duration string for logs.
func FormatDuration(value time.Duration) string {
	switch {
	case value < time.Second:
		return value.Round(10 * time.Millisecond).String()
	case value < time.Minute:
		return value.Round(100 * time.Millisecond).String()
	default:
		return value.Round(time.Second).String()
	}
}

type prettyConsoleEncoder struct {
	base    zapcore.Encoder
	context *zapcore.MapObjectEncoder
}

func newPrettyConsoleEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	return &prettyConsoleEncoder{
		base:    zapcore.NewConsoleEncoder(cfg),
		context: zapcore.NewMapObjectEncoder(),
	}
}

func (e *prettyConsoleEncoder) Clone() zapcore.Encoder {
	clone := &prettyConsoleEncoder{
		base:    e.base.Clone(),
		context: zapcore.NewMapObjectEncoder(),
	}
	for key, value := range e.context.Fields {
		clone.context.Fields[key] = cloneFieldValue(value)
	}
	return clone
}

func (e *prettyConsoleEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	line, err := e.base.Clone().EncodeEntry(entry, nil)
	if err != nil {
		return nil, err
	}

	fieldEncoder := zapcore.NewMapObjectEncoder()
	for key, value := range e.context.Fields {
		fieldEncoder.Fields[key] = cloneFieldValue(value)
	}
	for _, field := range fields {
		field.AddTo(fieldEncoder)
	}

	renderedLine := strings.TrimRight(line.String(), "\n")
	line.Reset()
	if renderedLine != "" {
		line.AppendString(renderedLine)
	}
	if len(fieldEncoder.Fields) > 0 {
		prettyJSON, err := json.MarshalIndent(fieldEncoder.Fields, "", "  ")
		if err != nil {
			return nil, err
		}
		if renderedLine != "" {
			line.AppendByte('\n')
		}
		line.AppendString(string(prettyJSON))
	}
	line.AppendByte('\n')
	return line, nil
}

func (e *prettyConsoleEncoder) AddArray(key string, marshaler zapcore.ArrayMarshaler) error {
	return e.context.AddArray(key, marshaler)
}

func (e *prettyConsoleEncoder) AddObject(key string, marshaler zapcore.ObjectMarshaler) error {
	return e.context.AddObject(key, marshaler)
}

func (e *prettyConsoleEncoder) AddBinary(key string, value []byte) {
	e.context.AddBinary(key, value)
}

func (e *prettyConsoleEncoder) AddByteString(key string, value []byte) {
	e.context.AddByteString(key, value)
}

func (e *prettyConsoleEncoder) AddBool(key string, value bool) {
	e.context.AddBool(key, value)
}

func (e *prettyConsoleEncoder) AddComplex128(key string, value complex128) {
	e.context.AddComplex128(key, value)
}

func (e *prettyConsoleEncoder) AddComplex64(key string, value complex64) {
	e.context.AddComplex64(key, value)
}

func (e *prettyConsoleEncoder) AddDuration(key string, value time.Duration) {
	e.context.AddDuration(key, value)
}

func (e *prettyConsoleEncoder) AddFloat64(key string, value float64) {
	e.context.AddFloat64(key, value)
}

func (e *prettyConsoleEncoder) AddFloat32(key string, value float32) {
	e.context.AddFloat32(key, value)
}

func (e *prettyConsoleEncoder) AddInt(key string, value int) {
	e.context.AddInt(key, value)
}

func (e *prettyConsoleEncoder) AddInt64(key string, value int64) {
	e.context.AddInt64(key, value)
}

func (e *prettyConsoleEncoder) AddInt32(key string, value int32) {
	e.context.AddInt32(key, value)
}

func (e *prettyConsoleEncoder) AddInt16(key string, value int16) {
	e.context.AddInt16(key, value)
}

func (e *prettyConsoleEncoder) AddInt8(key string, value int8) {
	e.context.AddInt8(key, value)
}

func (e *prettyConsoleEncoder) AddString(key, value string) {
	e.context.AddString(key, value)
}

func (e *prettyConsoleEncoder) AddTime(key string, value time.Time) {
	e.context.AddTime(key, value)
}

func (e *prettyConsoleEncoder) AddUint(key string, value uint) {
	e.context.AddUint(key, value)
}

func (e *prettyConsoleEncoder) AddUint64(key string, value uint64) {
	e.context.AddUint64(key, value)
}

func (e *prettyConsoleEncoder) AddUint32(key string, value uint32) {
	e.context.AddUint32(key, value)
}

func (e *prettyConsoleEncoder) AddUint16(key string, value uint16) {
	e.context.AddUint16(key, value)
}

func (e *prettyConsoleEncoder) AddUint8(key string, value uint8) {
	e.context.AddUint8(key, value)
}

func (e *prettyConsoleEncoder) AddUintptr(key string, value uintptr) {
	e.context.AddUintptr(key, value)
}

func (e *prettyConsoleEncoder) AddReflected(key string, value interface{}) error {
	return e.context.AddReflected(key, value)
}

func (e *prettyConsoleEncoder) OpenNamespace(key string) {
	e.context.OpenNamespace(key)
}

func cloneFieldValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, inner := range typed {
			cloned[key] = cloneFieldValue(inner)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for i, inner := range typed {
			cloned[i] = cloneFieldValue(inner)
		}
		return cloned
	default:
		return typed
	}
}

// CommandStderr captures subprocess stderr and only mirrors it when verbose mode is enabled.
type CommandStderr struct {
	buffer  bytes.Buffer
	visible io.Writer
	verbose bool
}

// NewCommandStderr creates a subprocess stderr writer for the selected verbosity.
func NewCommandStderr(visible io.Writer, verbose bool) *CommandStderr {
	return &CommandStderr{visible: visible, verbose: verbose}
}

// Write records stderr output and mirrors it when verbose mode is enabled.
func (w *CommandStderr) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}

	if _, err := w.buffer.Write(p); err != nil {
		return 0, err
	}
	if !w.verbose || w.visible == nil {
		return len(p), nil
	}
	if _, err := w.visible.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// String returns the captured stderr contents with surrounding whitespace trimmed.
func (w *CommandStderr) String() string {
	if w == nil {
		return ""
	}
	return strings.TrimSpace(w.buffer.String())
}
