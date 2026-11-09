package db

import (
	"log/slog"
	"strconv"
	"time"

	"gorm.io/gorm"
)

type BaseModel struct {
	ID uint64 `gorm:"column:id;primaryKey;autoIncrement;comment:ID" json:"id"`
}

func (m BaseModel) LogAttr() []slog.Attr {
	return []slog.Attr{slog.Uint64("id", m.ID)}
}

func JoinUint64(nums []uint64, sep string) string {
	switch len(nums) {
	case 0:
		return ""
	case 1:
		return strconv.FormatUint(nums[0], 10)
	}

	buf := make([]byte, 0, len(nums)*10+(len(nums)-1)*len(sep))
	for i, v := range nums {
		if i > 0 {
			buf = append(buf, sep...)
		}
		buf = strconv.AppendUint(buf, v, 10)
	}
	return string(buf)
}

// MapTo maps a slice of type T to a slice of type R using the provided function.
func MapTo[T any, R any](ms []T, f func(T) R) []R {
	out := make([]R, len(ms))
	for i, m := range ms {
		out[i] = f(m)
	}
	return out
}

// MapToUint64s maps a slice of type T to a slice of uint64 using the provided function.
func MapToUint64s[T any](ms []T, f func(T) uint64) []uint64 {
	return MapTo(ms, f)
}

type StandardModel struct {
	BaseModel
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;comment:Created Time" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime;comment:Updated Time" json:"updated_at"`
}

func (m StandardModel) LogAttr() []slog.Attr {
	return append(
		m.BaseModel.LogAttr(),
		slog.String("created_at", fmtTime(m.CreatedAt)),
		slog.String("updated_at", fmtTime(m.UpdatedAt)),
	)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.DateTime)
}

type SoftDeleteModel struct {
	StandardModel

	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index;comment:Deleted Time" json:"-"`
}

func (m SoftDeleteModel) LogAttr() []slog.Attr {
	attrs := m.StandardModel.LogAttr()
	if m.DeletedAt.Valid {
		attrs = append(attrs, slog.String("deleted_at", fmtTime(m.DeletedAt.Time)))
	}
	return attrs
}
