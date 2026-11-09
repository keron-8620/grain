package filter

import (
	"fmt"
	"math"
	"reflect"
	"slices"
	"time"

	"emperror.dev/errors"
)

// ErrInvalidListOption is returned when a client-supplied list option (such as filter or order_by)
// is malformed or references a field outside the allowlist.
var ErrInvalidListOption = errors.New("invalid list query option")

// ListFilterOp is the constrained set of AIP-160 comparison operators supported by the system.
type ListFilterOp string

const (
	ListFilterEquals        ListFilterOp = "="
	ListFilterNotEquals     ListFilterOp = "!="
	ListFilterContains      ListFilterOp = "contains"
	ListFilterGreaterThan   ListFilterOp = ">"
	ListFilterGreaterEquals ListFilterOp = ">="
	ListFilterLessThan      ListFilterOp = "<"
	ListFilterLessEquals    ListFilterOp = "<="
	ListFilterIn            ListFilterOp = "in"
	ListFilterNotIn         ListFilterOp = "not in"
	ListFilterIsNull        ListFilterOp = "is null"
	ListFilterIsNotNull     ListFilterOp = "is not null"
)

// ListFilterType is the declared type of a filterable field.
type ListFilterType string

const (
	ListFilterString ListFilterType = "string"
	ListFilterBool   ListFilterType = "bool"
	ListFilterUint   ListFilterType = "uint"
	ListFilterInt    ListFilterType = "int"
	ListFilterFloat  ListFilterType = "float"
	ListFilterTime   ListFilterType = "time"
)

// ListFilterField declares a filterable field and the operators it accepts.
// Exported per resource so the transport layer can type-check AIP filters.
type ListFilterField struct {
	Name string
	Type ListFilterType
	Ops  []ListFilterOp
}

// ListFilter is a single, already type-checked filter comparison.
type ListFilter struct {
	Field string
	Op    ListFilterOp
	Value any
}

// ValidateListFilters re-validates parsed filters against the resource declarations
// (defense in depth: the storage layer must never receive an undeclared field or operator).
func ValidateListFilters(filters []ListFilter, fields []ListFilterField) error {
	for _, filter := range filters {
		var declaration *ListFilterField
		for i := range fields {
			if fields[i].Name == filter.Field {
				declaration = &fields[i]
				break
			}
		}
		if declaration == nil {
			return fmt.Errorf("%w: field %q is not filterable", ErrInvalidListOption, filter.Field)
		}
		allowed := slices.Contains(declaration.Ops, filter.Op)
		if !allowed {
			return fmt.Errorf("%w: operator %q is not allowed on field %q", ErrInvalidListOption, filter.Op, filter.Field)
		}
		if err := ValidateFilterValue(filter, *declaration); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFilterValue validates the value of a filter against the declared field type.
func ValidateFilterValue(filter ListFilter, field ListFilterField) error {
	if filter.Op == ListFilterIsNull || filter.Op == ListFilterIsNotNull {
		return validateDeclaredType(field)
	}
	if filter.Op == ListFilterIn || filter.Op == ListFilterNotIn {
		if filter.Value == nil {
			return fmt.Errorf("%w: field %q with %q operator expects a non-empty slice", ErrInvalidListOption, field.Name, filter.Op)
		}
		rv := reflect.ValueOf(filter.Value)
		if (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) || rv.Len() == 0 {
			return fmt.Errorf("%w: field %q with %q operator expects a non-empty slice", ErrInvalidListOption, field.Name, filter.Op)
		}
		for i := 0; i < rv.Len(); i++ {
			if err := validateSingleFilterValue(rv.Index(i).Interface(), field); err != nil {
				return err
			}
		}
		return nil
	}
	return validateSingleFilterValue(filter.Value, field)
}

func validateDeclaredType(field ListFilterField) error {
	switch field.Type {
	case ListFilterString, ListFilterBool, ListFilterUint, ListFilterInt, ListFilterFloat, ListFilterTime:
		return nil
	default:
		return fmt.Errorf("%w: field %q has an unsupported type", ErrInvalidListOption, field.Name)
	}
}

func validateSingleFilterValue(val any, field ListFilterField) error {
	switch field.Type {
	case ListFilterString:
		if _, ok := val.(string); !ok {
			return fmt.Errorf("%w: field %q expects a string", ErrInvalidListOption, field.Name)
		}
	case ListFilterBool:
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("%w: field %q expects a bool", ErrInvalidListOption, field.Name)
		}
	case ListFilterUint:
		switch v := val.(type) {
		case uint, uint64, uint32, uint16, uint8:
		case int:
			if v < 0 {
				return fmt.Errorf("%w: field %q expects a non-negative integer", ErrInvalidListOption, field.Name)
			}
		case int64:
			if v < 0 {
				return fmt.Errorf("%w: field %q expects a non-negative integer", ErrInvalidListOption, field.Name)
			}
		case int32:
			if v < 0 {
				return fmt.Errorf("%w: field %q expects a non-negative integer", ErrInvalidListOption, field.Name)
			}
		case int16:
			if v < 0 {
				return fmt.Errorf("%w: field %q expects a non-negative integer", ErrInvalidListOption, field.Name)
			}
		case int8:
			if v < 0 {
				return fmt.Errorf("%w: field %q expects a non-negative integer", ErrInvalidListOption, field.Name)
			}
		default:
			return fmt.Errorf("%w: field %q expects an integer", ErrInvalidListOption, field.Name)
		}
	case ListFilterInt:
		switch v := val.(type) {
		case int, int64, int32, int16, int8, uint32, uint16, uint8:
		case uint:
			if uint64(v) > math.MaxInt64 {
				return fmt.Errorf("%w: field %q integer value overflows int64", ErrInvalidListOption, field.Name)
			}
		case uint64:
			if v > math.MaxInt64 {
				return fmt.Errorf("%w: field %q integer value overflows int64", ErrInvalidListOption, field.Name)
			}
		default:
			return fmt.Errorf("%w: field %q expects an integer", ErrInvalidListOption, field.Name)
		}
	case ListFilterFloat:
		switch v := val.(type) {
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return fmt.Errorf("%w: field %q expects a finite float", ErrInvalidListOption, field.Name)
			}
		case float32:
			if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
				return fmt.Errorf("%w: field %q expects a finite float", ErrInvalidListOption, field.Name)
			}
		case int, int64, int32, int16, int8, uint, uint64, uint32, uint16, uint8:
		default:
			return fmt.Errorf("%w: field %q expects a float", ErrInvalidListOption, field.Name)
		}
	case ListFilterTime:
		switch v := val.(type) {
		case time.Time:
			if v.IsZero() {
				return fmt.Errorf("%w: field %q expects a non-zero time", ErrInvalidListOption, field.Name)
			}
		case *time.Time:
			if v == nil || v.IsZero() {
				return fmt.Errorf("%w: field %q expects a non-zero time", ErrInvalidListOption, field.Name)
			}
		case string:
			if !isValidTimeString(v) {
				return fmt.Errorf("%w: field %q expects a valid time (RFC3339 or YYYY-MM-DD[ HH:MM:SS])", ErrInvalidListOption, field.Name)
			}
		default:
			return fmt.Errorf("%w: field %q expects a time.Time or time string", ErrInvalidListOption, field.Name)
		}
	default:
		return fmt.Errorf("%w: field %q has an unsupported type", ErrInvalidListOption, field.Name)
	}
	return nil
}

func isValidTimeString(s string) bool {
	if s == "" {
		return false
	}
	for _, layout := range []string{
		time.RFC3339,
		time.RFC3339Nano,
		time.DateTime,
		time.DateOnly,
	} {
		if _, err := time.Parse(layout, s); err == nil {
			return true
		}
	}
	return false
}

// StringFilterOps is the operator set accepted for string fields.
func StringFilterOps() []ListFilterOp {
	return []ListFilterOp{ListFilterEquals, ListFilterNotEquals, ListFilterContains}
}

// EqualityFilterOps is the operator set accepted for bool fields.
func EqualityFilterOps() []ListFilterOp {
	return []ListFilterOp{ListFilterEquals, ListFilterNotEquals}
}

// NumericFilterOps is the operator set accepted for numeric fields.
func NumericFilterOps() []ListFilterOp {
	return []ListFilterOp{
		ListFilterEquals, ListFilterNotEquals,
		ListFilterGreaterThan, ListFilterGreaterEquals,
		ListFilterLessThan, ListFilterLessEquals,
	}
}

// IntFilterOps is the operator set accepted for signed integer fields.
func IntFilterOps() []ListFilterOp {
	return NumericFilterOps()
}

// FloatFilterOps is the operator set accepted for floating-point fields.
func FloatFilterOps() []ListFilterOp {
	return NumericFilterOps()
}

// TimeFilterOps is the operator set accepted for time/timestamp fields.
func TimeFilterOps() []ListFilterOp {
	return NumericFilterOps()
}

// SetFilterOps returns the set membership operators (in, not in).
func SetFilterOps() []ListFilterOp {
	return []ListFilterOp{ListFilterIn, ListFilterNotIn}
}

// NullFilterOps returns the nullability check operators (is null, is not null).
func NullFilterOps() []ListFilterOp {
	return []ListFilterOp{ListFilterIsNull, ListFilterIsNotNull}
}
