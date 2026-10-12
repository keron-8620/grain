package db

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

type BaseModel struct {
	ID uint32 `gorm:"column:id;primary_key;AUTO_INCREMENT;comment:ID" json:"id"`
}

func (m BaseModel) LogAttr() slog.Attr {
	return slog.Int64("id", int64(m.ID))
}

// BigBaseModel provides a 64-bit auto-increment primary key (BIGINT)
// to prevent ID exhaustion in high-volume tables (logs, events, outbox records).
type BigBaseModel struct {
	ID uint64 `gorm:"column:id;primary_key;AUTO_INCREMENT;comment:ID" json:"id"`
}

func (m BigBaseModel) LogAttr() slog.Attr {
	return slog.Uint64("id", m.ID)
}

func JoinUint32(nums []uint32, sep string) string {
	switch len(nums) {
	case 0:
		return ""
	case 1:
		return strconv.FormatUint(uint64(nums[0]), 10)
	}
	var b strings.Builder
	// uint32 max is 4294967295 (10 digits)
	b.Grow(len(nums)*10 + (len(nums)-1)*len(sep))
	for i, v := range nums {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

func JoinUint64(nums []uint64, sep string) string {
	switch len(nums) {
	case 0:
		return ""
	case 1:
		return strconv.FormatUint(nums[0], 10)
	}
	var b strings.Builder
	// uint64 max is 18446744073709551615 (20 digits)
	b.Grow(len(nums)*20 + (len(nums)-1)*len(sep))
	for i, v := range nums {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(strconv.FormatUint(v, 10))
	}
	return b.String()
}

type StandardModel struct {
	BaseModel

	CreatedAt time.Time      `gorm:"column:created_at;autoCreateTime;comment:Created Time" json:"created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at;autoUpdateTime;comment:Updated Time" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index;comment:Deleted Time" json:"-"`
}

func (m StandardModel) LogAttr() []slog.Attr {
	return []slog.Attr{
		slog.Int64("id", int64(m.ID)),
		slog.String("created_at", m.CreatedAt.Format(time.DateTime)),
		slog.String("updated_at", m.UpdatedAt.Format(time.DateTime)),
	}
}

// StandardModel64 embeds BigBaseModel with standard audit timestamps and soft delete.
type StandardModel64 struct {
	BigBaseModel

	CreatedAt time.Time      `gorm:"column:created_at;autoCreateTime;comment:Created Time" json:"created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at;autoUpdateTime;comment:Updated Time" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index;comment:Deleted Time" json:"-"`
}

func (m StandardModel64) LogAttr() []slog.Attr {
	return []slog.Attr{
		slog.Uint64("id", m.ID),
		slog.String("created_at", m.CreatedAt.Format(time.DateTime)),
		slog.String("updated_at", m.UpdatedAt.Format(time.DateTime)),
	}
}
