package filter

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterOps(t *testing.T) {
	strOps := StringFilterOps()
	assert.Contains(t, strOps, ListFilterEquals)
	assert.Contains(t, strOps, ListFilterNotEquals)
	assert.Contains(t, strOps, ListFilterContains)

	eqOps := EqualityFilterOps()
	assert.Contains(t, eqOps, ListFilterEquals)
	assert.Contains(t, eqOps, ListFilterNotEquals)

	numOps := NumericFilterOps()
	assert.Contains(t, numOps, ListFilterEquals)
	assert.Contains(t, numOps, ListFilterNotEquals)
	assert.Contains(t, numOps, ListFilterGreaterThan)
	assert.Contains(t, numOps, ListFilterGreaterEquals)
	assert.Contains(t, numOps, ListFilterLessThan)
	assert.Contains(t, numOps, ListFilterLessEquals)
}

func TestValidateListFilters(t *testing.T) {
	fields := []ListFilterField{
		{Name: "username", Type: ListFilterString, Ops: StringFilterOps()},
		{Name: "is_active", Type: ListFilterBool, Ops: EqualityFilterOps()},
		{Name: "age", Type: ListFilterUint, Ops: NumericFilterOps()},
	}

	t.Run("valid filters pass validation", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "username", Op: ListFilterEquals, Value: "alice"},
			{Field: "is_active", Op: ListFilterEquals, Value: true},
			{Field: "age", Op: ListFilterGreaterEquals, Value: uint(18)},
			{Field: "age", Op: ListFilterEquals, Value: uint64(20)},
			{Field: "age", Op: ListFilterEquals, Value: uint32(25)},
			{Field: "age", Op: ListFilterEquals, Value: uint16(30)},
			{Field: "age", Op: ListFilterEquals, Value: uint8(35)},
			{Field: "age", Op: ListFilterLessThan, Value: int64(100)},
			{Field: "age", Op: ListFilterEquals, Value: int(40)},
			{Field: "age", Op: ListFilterEquals, Value: int32(45)},
			{Field: "age", Op: ListFilterEquals, Value: int16(50)},
			{Field: "age", Op: ListFilterEquals, Value: int8(55)},
		}
		err := ValidateListFilters(filters, fields)
		assert.NoError(t, err)
	})

	t.Run("negative integer on uint field returns error", func(t *testing.T) {
		for _, negVal := range []any{int(-1), int64(-10), int32(-5), int16(-2), int8(-1)} {
			filters := []ListFilter{
				{Field: "age", Op: ListFilterEquals, Value: negVal},
			}
			err := ValidateListFilters(filters, fields)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidListOption)
			assert.Contains(t, err.Error(), "expects a non-negative integer")
		}
	})

	t.Run("unsupported field returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "secret", Op: ListFilterEquals, Value: "xyz"},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "field \"secret\" is not filterable")
	})

	t.Run("disallowed operator returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "username", Op: ListFilterGreaterThan, Value: "alice"},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "operator \">\" is not allowed on field \"username\"")
	})

	t.Run("string type mismatch returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "username", Op: ListFilterEquals, Value: 123},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "expects a string")
	})

	t.Run("bool type mismatch returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "is_active", Op: ListFilterEquals, Value: "true"},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "expects a bool")
	})

	t.Run("uint type mismatch returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "age", Op: ListFilterEquals, Value: "twenty"},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "expects an integer")
	})

	t.Run("unsupported field type in declaration returns error", func(t *testing.T) {
		badFields := []ListFilterField{
			{Name: "data", Type: ListFilterType("unknown_custom_type"), Ops: []ListFilterOp{ListFilterEquals}},
		}
		filters := []ListFilter{
			{Field: "data", Op: ListFilterEquals, Value: 3.14},
		}
		err := ValidateListFilters(filters, badFields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "unsupported type")
	})

	t.Run("extended types and operators pass validation", func(t *testing.T) {
		extFields := []ListFilterField{
			{Name: "status", Type: ListFilterString, Ops: append(StringFilterOps(), SetFilterOps()...)},
			{Name: "balance", Type: ListFilterInt, Ops: append(IntFilterOps(), SetFilterOps()...)},
			{Name: "rate", Type: ListFilterFloat, Ops: FloatFilterOps()},
			{Name: "created_at", Type: ListFilterTime, Ops: append(TimeFilterOps(), NullFilterOps()...)},
		}

		validFilters := []ListFilter{
			{Field: "status", Op: ListFilterIn, Value: []string{"active", "pending"}},
			{Field: "status", Op: ListFilterNotIn, Value: []string{"deleted"}},
			{Field: "balance", Op: ListFilterEquals, Value: -500},
			{Field: "balance", Op: ListFilterIn, Value: []int{-10, 0, 10}},
			{Field: "rate", Op: ListFilterGreaterThan, Value: 3.14},
			{Field: "rate", Op: ListFilterLessEquals, Value: 100},
			{Field: "created_at", Op: ListFilterGreaterEquals, Value: "2026-01-01 00:00:00"},
			{Field: "created_at", Op: ListFilterIsNull, Value: nil},
			{Field: "created_at", Op: ListFilterIsNotNull, Value: nil},
		}
		require.NoError(t, ValidateListFilters(validFilters, extFields))
	})

	t.Run("IN operator with empty slice returns error", func(t *testing.T) {
		extFields := []ListFilterField{
			{Name: "status", Type: ListFilterString, Ops: SetFilterOps()},
		}
		filters := []ListFilter{
			{Field: "status", Op: ListFilterIn, Value: []string{}},
		}
		err := ValidateListFilters(filters, extFields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "expects a non-empty slice")
	})

	t.Run("IN operator with non-slice returns error", func(t *testing.T) {
		extFields := []ListFilterField{
			{Name: "status", Type: ListFilterString, Ops: SetFilterOps()},
		}
		filters := []ListFilter{
			{Field: "status", Op: ListFilterIn, Value: "not-a-slice"},
		}
		err := ValidateListFilters(filters, extFields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "expects a non-empty slice")

		// nil value for IN
		err = ValidateListFilters([]ListFilter{{Field: "status", Op: ListFilterIn, Value: nil}}, extFields)
		require.ErrorIs(t, err, ErrInvalidListOption)

		// invalid element inside IN slice
		err = ValidateListFilters([]ListFilter{{Field: "status", Op: ListFilterIn, Value: []any{"ok", 123}}}, extFields)
		require.ErrorIs(t, err, ErrInvalidListOption)
	})

	t.Run("int, float, and time validation edge cases", func(t *testing.T) {
		extFields := []ListFilterField{
			{Name: "balance", Type: ListFilterInt, Ops: IntFilterOps()},
			{Name: "rate", Type: ListFilterFloat, Ops: FloatFilterOps()},
			{Name: "created_at", Type: ListFilterTime, Ops: append(TimeFilterOps(), NullFilterOps()...)},
		}

		// Valid int variants
		for _, v := range []any{int(-1), int64(-100), int32(10), int16(5), int8(-2), uint(10), uint64(100), uint32(5), uint16(2), uint8(1)} {
			require.NoError(t, ValidateListFilters([]ListFilter{{Field: "balance", Op: ListFilterEquals, Value: v}}, extFields))
		}
		// Overflow uint64 / uint on int field
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "balance", Op: ListFilterEquals, Value: uint64(math.MaxUint64)}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "balance", Op: ListFilterEquals, Value: uint(math.MaxUint64)}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "balance", Op: ListFilterEquals, Value: "not-int"}}, extFields), ErrInvalidListOption)

		// Valid float variants
		require.NoError(t, ValidateListFilters([]ListFilter{{Field: "rate", Op: ListFilterEquals, Value: float32(1.5)}}, extFields))
		require.NoError(t, ValidateListFilters([]ListFilter{{Field: "rate", Op: ListFilterEquals, Value: float64(2.5)}}, extFields))
		// NaN / Inf / non-float
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "rate", Op: ListFilterEquals, Value: math.NaN()}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "rate", Op: ListFilterEquals, Value: float32(math.Inf(1))}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "rate", Op: ListFilterEquals, Value: "bad"}}, extFields), ErrInvalidListOption)

		// Valid time variants
		now := time.Now()
		require.NoError(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: now}}, extFields))
		require.NoError(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: &now}}, extFields))
		require.NoError(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: "2026-10-13"}}, extFields))
		require.NoError(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: now.Format(time.RFC3339)}}, extFields))

		// Invalid time variants
		var nilTime *time.Time
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: time.Time{}}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: nilTime}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: ""}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: "not-a-date"}}, extFields), ErrInvalidListOption)
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "created_at", Op: ListFilterEquals, Value: 12345}}, extFields), ErrInvalidListOption)

		// Unsupported declared type with IS NULL
		badNullField := []ListFilterField{{Name: "x", Type: ListFilterType("bad"), Ops: NullFilterOps()}}
		require.ErrorIs(t, ValidateListFilters([]ListFilter{{Field: "x", Op: ListFilterIsNull}}, badNullField), ErrInvalidListOption)
	})
}
