package errorx

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"

	emperror "emperror.dev/errors"
)

type Error struct {
	Code     BizCode `json:"code"`
	Msg      string  `json:"msg"`
	Details  []any   `json:"details,omitempty"`
	metadata map[string]any
	cause    error
}

func New(code BizCode, message string) *Error {
	if message == "" {
		message = defaultMsg(code)
	}
	return &Error{
		Code: code,
		Msg:  message,
	}
}

func Errorf(code BizCode, format string, args ...any) *Error {
	return New(code, fmt.Sprintf(format, args...))
}

func Wrap(cause error, code BizCode, message string) *Error {
	if cause == nil {
		return nil
	}
	err := New(code, message)
	err.cause = emperror.WithStackIf(cause)
	return err
}

func Wrapf(cause error, code BizCode, format string, args ...any) *Error {
	return Wrap(cause, code, fmt.Sprintf(format, args...))
}

func Clone(err *Error) *Error {
	if err == nil {
		return nil
	}
	meta := make(map[string]any, len(err.metadata))
	maps.Copy(meta, err.metadata)
	return &Error{
		Code:     err.Code,
		Msg:      err.Msg,
		Details:  append([]any(nil), err.Details...),
		metadata: meta,
		cause:    err.cause,
	}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.cause != nil {
		return fmt.Sprintf("error: code = %d msg = %s, cause = %v", e.Code, e.Msg, e.cause)
	}
	return fmt.Sprintf("error: code = %d msg = %s", e.Code, e.Msg)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *Error) Is(target error) bool {
	if e == nil {
		return target == nil
	}
	if target == nil {
		return false
	}
	if te, ok := target.(*Error); ok {
		return te.Code == e.Code
	}
	return false
}

func (e *Error) WithField(key string, value any) *Error {
	if e == nil {
		return nil
	}
	err := Clone(e)
	err.metadata[key] = value
	return err
}

func (e *Error) WithMetadata(fields map[string]any) *Error {
	if e == nil {
		return nil
	}
	err := Clone(e)
	maps.Copy(err.metadata, fields)
	return err
}

func (e *Error) WithDetails(details ...any) *Error {
	if e == nil {
		return nil
	}
	err := Clone(e)
	err.Details = append(err.Details, details...)
	return err
}

func (e *Error) WithCause(cause error) *Error {
	if e == nil || cause == nil {
		return e
	}
	err := Clone(e)
	err.cause = emperror.WithStackIf(cause)
	return err
}

func (e *Error) Metadata() map[string]any {
	if e == nil {
		return nil
	}
	meta := make(map[string]any, len(e.metadata))
	maps.Copy(meta, e.metadata)
	return meta
}

func (e *Error) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			fmt.Fprintf(s, "error: code = %d msg = %s\n", e.Code, e.Msg)
			if len(e.Details) > 0 {
				fmt.Fprintf(s, "details: %v\n", e.Details)
			}
			if len(e.metadata) > 0 {
				fmt.Fprintf(s, "metadata: %v\n", e.metadata)
			}
			if e.cause != nil {
				fmt.Fprintf(s, "%+v", e.cause)
			}
			return
		}
		fallthrough
	case 's':
		fmt.Fprintf(s, "%s", e.Error())
	case 'q':
		fmt.Fprintf(s, "%q", e.Error())
	default:
		fmt.Fprintf(s, "%%!%c(errorx.Error=%s)", verb, e.Error())
	}

}

func (e *Error) LogValue() slog.Value {
	if e == nil {
		return slog.Value{}
	}
	attrs := []slog.Attr{
		slog.Int("code", int(e.Code)),
		slog.String("msg", e.Msg),
	}
	if len(e.Details) > 0 {
		attrs = append(attrs, slog.Any("details", e.Details))
	}
	if len(e.metadata) > 0 {
		attrs = append(attrs, slog.Any("metadata", e.metadata))
	}
	if e.cause != nil {
		attrs = append(attrs,
			slog.String("cause", e.cause.Error()),
			slog.String("stack", fmt.Sprintf("%+v", e.cause)),
		)
	}
	return slog.GroupValue(attrs...)
}

func FromError(err error) (*Error, bool) {
	if err == nil {
		return nil, false
	}
	if e, ok := err.(*Error); ok {
		return e, true
	}
	if e, ok := errors.AsType[*Error](err); ok {
		return e, true
	}
	return nil, false
}

func IsCode(err error, code BizCode) bool {
	if e, ok := FromError(err); ok {
		return e.Code == code
	}
	return false
}
