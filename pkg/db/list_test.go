package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateUpdateMask(t *testing.T) {
	allowed := []string{"user_name", "email_address", "is_active"}

	t.Run("empty mask returns nil", func(t *testing.T) {
		res, err := ValidateUpdateMask(nil, allowed)
		require.NoError(t, err)
		assert.Nil(t, res)

		res, err = ValidateUpdateMask([]string{}, allowed)
		require.NoError(t, err)
		assert.Nil(t, res)
	})

	t.Run("wildcard returns asterisk", func(t *testing.T) {
		res, err := ValidateUpdateMask([]string{"*"}, allowed)
		require.NoError(t, err)
		assert.Equal(t, []string{"*"}, res)
	})

	t.Run("empty path in mask returns error", func(t *testing.T) {
		_, err := ValidateUpdateMask([]string{"user_name", "  "}, allowed)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidUpdateMask)
	})

	t.Run("canonicalizes snake_case and camelCase", func(t *testing.T) {
		res, err := ValidateUpdateMask([]string{"userName", "email_address", "isActive"}, allowed)
		require.NoError(t, err)
		assert.Equal(t, []string{"user_name", "email_address", "is_active"}, res)
	})

	t.Run("unauthorized field returns error", func(t *testing.T) {
		_, err := ValidateUpdateMask([]string{"user_name", "password"}, allowed)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidUpdateMask)
		assert.Contains(t, err.Error(), "field \"password\" is not updatable")
	})
}

func TestFilterOps(t *testing.T) {
	strOps := StringFilterOps()
	assert.Contains(t, strOps, ListFilterEquals)
	assert.Contains(t, strOps, ListFilterNotEquals)
	assert.Contains(t, strOps, ListFilterContains)
	assert.Equal(t, strOps, stringFilterOps())

	eqOps := EqualityFilterOps()
	assert.Contains(t, eqOps, ListFilterEquals)
	assert.Contains(t, eqOps, ListFilterNotEquals)
	assert.Equal(t, eqOps, equalityFilterOps())

	numOps := NumericFilterOps()
	assert.Contains(t, numOps, ListFilterEquals)
	assert.Contains(t, numOps, ListFilterNotEquals)
	assert.Contains(t, numOps, ListFilterGreaterThan)
	assert.Contains(t, numOps, ListFilterGreaterEquals)
	assert.Contains(t, numOps, ListFilterLessThan)
	assert.Contains(t, numOps, ListFilterLessEquals)
	assert.Equal(t, numOps, numericFilterOps())
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
			{Field: "age", Op: ListFilterLessThan, Value: int64(100)},
		}
		err := ValidateListFilters(filters, fields)
		assert.NoError(t, err)
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

	t.Run("forbidden operator on field returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "is_active", Op: ListFilterContains, Value: true},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "operator \"contains\" is not allowed on field \"is_active\"")
	})

	t.Run("type mismatch on string field returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "username", Op: ListFilterEquals, Value: 123},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "expects a string")
	})

	t.Run("type mismatch on bool field returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "is_active", Op: ListFilterEquals, Value: "true"},
		}
		err := ValidateListFilters(filters, fields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "expects a bool")
	})

	t.Run("type mismatch on uint field returns error", func(t *testing.T) {
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
			{Name: "data", Type: ListFilterType("float"), Ops: []ListFilterOp{ListFilterEquals}},
		}
		filters := []ListFilter{
			{Field: "data", Op: ListFilterEquals, Value: 3.14},
		}
		err := ValidateListFilters(filters, badFields)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "unsupported type")
	})
}

func TestApplyListFilters(t *testing.T) {
	c := &DBConf{
		Type:            "sqlite",
		Dsn:             fmt.Sprintf("file:%s?mode=memory&cache=shared", uuid.NewString()),
		MaxIdleConns:    10,
		MaxOpenConns:    100,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
	}
	db, err := NewGormDB(c, nil)
	require.NoError(t, err)
	defer func() { _ = CloseGormDB(db) }()

	type TestItem struct {
		ID       uint   `gorm:"primaryKey"`
		Title    string `gorm:"column:title"`
		Score    int    `gorm:"column:score"`
		IsActive bool   `gorm:"column:is_active"`
	}
	require.NoError(t, db.AutoMigrate(&TestItem{}))

	items := []TestItem{
		{Title: "Apple Fruit", Score: 80, IsActive: true},
		{Title: "Banana Fruit", Score: 90, IsActive: true},
		{Title: "Cherry Snack", Score: 60, IsActive: false},
	}
	for _, it := range items {
		require.NoError(t, db.Create(&it).Error)
	}

	t.Run("nil db returns error", func(t *testing.T) {
		_, err := ApplyListFilters(nil, []ListFilter{{Field: "title", Op: ListFilterEquals, Value: "test"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database instance is nil")
	})

	t.Run("empty filters returns unmodified db", func(t *testing.T) {
		resDB, err := ApplyListFilters(db, nil)
		require.NoError(t, err)
		assert.NotNil(t, resDB)
	})

	t.Run("apply equals and contains filters", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "title", Op: ListFilterContains, Value: "Fruit"},
			{Field: "is_active", Op: ListFilterEquals, Value: true},
		}
		q, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.NoError(t, err)

		var results []TestItem
		require.NoError(t, q.Find(&results).Error)
		assert.Len(t, results, 2)
	})

	t.Run("apply comparison operators", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "score", Op: ListFilterGreaterEquals, Value: 80},
			{Field: "score", Op: ListFilterLessThan, Value: 90},
		}
		q, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.NoError(t, err)

		var results []TestItem
		require.NoError(t, q.Find(&results).Error)
		require.Len(t, results, 1)
		assert.Equal(t, "Apple Fruit", results[0].Title)
	})

	t.Run("apply not equals and greater than", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "score", Op: ListFilterNotEquals, Value: 90},
			{Field: "score", Op: ListFilterGreaterThan, Value: 65},
		}
		q, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.NoError(t, err)

		var results []TestItem
		require.NoError(t, q.Find(&results).Error)
		require.Len(t, results, 1)
		assert.Equal(t, "Apple Fruit", results[0].Title)
	})

	t.Run("apply less or equals", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "score", Op: ListFilterLessEquals, Value: 60},
		}
		q, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.NoError(t, err)

		var results []TestItem
		require.NoError(t, q.Find(&results).Error)
		require.Len(t, results, 1)
		assert.Equal(t, "Cherry Snack", results[0].Title)
	})

	t.Run("apply contains filter with escaped wildcards", func(t *testing.T) {
		wildcardItem := TestItem{Title: "Discount 50% Off", Score: 50, IsActive: true}
		underscoreItem := TestItem{Title: "test_underscore_item", Score: 55, IsActive: true}
		require.NoError(t, db.Create(&wildcardItem).Error)
		require.NoError(t, db.Create(&underscoreItem).Error)

		// Search for literal "50%" - should match Discount 50% Off, but not anything else
		filters := []ListFilter{
			{Field: "title", Op: ListFilterContains, Value: "50%"},
		}
		q, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.NoError(t, err)

		var results []TestItem
		require.NoError(t, q.Find(&results).Error)
		require.Len(t, results, 1)
		assert.Equal(t, "Discount 50% Off", results[0].Title)

		// Search for literal "_underscore_" - should match test_underscore_item
		filters = []ListFilter{
			{Field: "title", Op: ListFilterContains, Value: "_underscore_"},
		}
		q, err = ApplyListFilters(db.Model(&TestItem{}), filters)
		require.NoError(t, err)

		results = nil
		require.NoError(t, q.Find(&results).Error)
		require.Len(t, results, 1)
		assert.Equal(t, "test_underscore_item", results[0].Title)
	})

	t.Run("invalid field name injection attempt", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "title; DROP TABLE users;--", Op: ListFilterEquals, Value: "test"},
		}
		_, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "invalid field name")
	})

	t.Run("empty field name returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "", Op: ListFilterEquals, Value: "test"},
		}
		_, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
	})

	t.Run("unsupported operator returns error", func(t *testing.T) {
		filters := []ListFilter{
			{Field: "score", Op: ListFilterOp("IN"), Value: []int{80, 90}},
		}
		_, err := ApplyListFilters(db.Model(&TestItem{}), filters)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidListOption)
		assert.Contains(t, err.Error(), "unsupported filter operator")
	})
}

func TestEscapeLikePattern(t *testing.T) {
	assert.Equal(t, "", EscapeLikePattern(""))
	assert.Equal(t, "normal text", EscapeLikePattern("normal text"))
	assert.Equal(t, `100\% discount`, EscapeLikePattern("100% discount"))
	assert.Equal(t, `user\_name`, EscapeLikePattern("user_name"))
	assert.Equal(t, `path\\to\\file`, EscapeLikePattern(`path\to\file`))
	assert.Equal(t, `\%mixed\\pattern\_100\%\%`, EscapeLikePattern(`%mixed\pattern_100%%`))
}

// -------------------- Page2LimitOffset Tests --------------------

func TestPage2LimitOffset(t *testing.T) {
	tests := []struct {
		name       string
		page       int
		size       int
		wantLimit  int
		wantOffset int
	}{
		{name: "normal page 1", page: 1, size: 10, wantLimit: 10, wantOffset: 0},
		{name: "normal page 2", page: 2, size: 10, wantLimit: 10, wantOffset: 10},
		{name: "normal page 3 size 20", page: 3, size: 20, wantLimit: 20, wantOffset: 40},
		{name: "page is zero defaults to page 1", page: 0, size: 15, wantLimit: 15, wantOffset: 0},
		{name: "page is negative defaults to page 1", page: -5, size: 15, wantLimit: 15, wantOffset: 0},
		{name: "size is zero defaults to DefaultPageSize (20)", page: 1, size: 0, wantLimit: DefaultPageSize, wantOffset: 0},
		{name: "size is negative defaults to DefaultPageSize (20)", page: 2, size: -10, wantLimit: DefaultPageSize, wantOffset: DefaultPageSize},
		{name: "size exceeds MaxSize (100) is clamped", page: 1, size: 200, wantLimit: 100, wantOffset: 0},
		{name: "page 5 with clamped MaxSize", page: 5, size: 150, wantLimit: 100, wantOffset: 400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLimit, gotOffset := Page2LimitOffset(tt.page, tt.size)
			assert.Equal(t, tt.wantLimit, gotLimit, "limit mismatch")
			assert.Equal(t, tt.wantOffset, gotOffset, "offset mismatch")
		})
	}
}
