package db

import (
	"fmt"
	"strings"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

// ErrInvalidListOption is returned when a client-supplied list option (such as filter or order_by)
// is malformed or references a field outside the allowlist.
var ErrInvalidListOption = errors.New("invalid list query option")

// ErrInvalidUpdateMask is returned when an update mask references an unknown or non-updatable field.
var ErrInvalidUpdateMask = errors.New("invalid update mask")

const (
	// DefaultPageSize is applied when a list request omits page_size.
	DefaultPageSize = 20
	// MaxPageSize caps how many rows a single list request can return.
	MaxPageSize = 100
)

// ValidateUpdateMask canonicalizes an AIP-134 update mask (accepting both snake_case and
// lowerCamelCase paths) against the resource's updatable fields. It returns the canonical
// snake_case paths; "*" means full replacement and is passed through.
func ValidateUpdateMask(mask []string, allowedFields []string) ([]string, error) {
	if len(mask) == 0 {
		return nil, nil
	}
	canonical := make(map[string]string, len(allowedFields))
	for _, field := range allowedFields {
		canonical[normalizeMaskPath(field)] = field
	}
	result := make([]string, 0, len(mask))
	for _, path := range mask {
		trimmed := strings.TrimSpace(path)
		if trimmed == "*" {
			return []string{"*"}, nil
		}
		if trimmed == "" {
			return nil, fmt.Errorf("%w: empty update field path", ErrInvalidUpdateMask)
		}
		field, ok := canonical[normalizeMaskPath(trimmed)]
		if !ok {
			return nil, fmt.Errorf("%w: field %q is not updatable", ErrInvalidUpdateMask, path)
		}
		result = append(result, field)
	}
	return result, nil
}

// normalizeMaskPath folds snake_case and camelCase spellings to the same key.
func normalizeMaskPath(path string) string {
	lower := strings.ToLower(strings.ReplaceAll(path, "_", ""))
	return lower
}

// ListFilterOp is the constrained set of AIP-160 comparison operators supported by IAM.
type ListFilterOp string

const (
	ListFilterEquals        ListFilterOp = "="
	ListFilterNotEquals     ListFilterOp = "!="
	ListFilterContains      ListFilterOp = "contains"
	ListFilterGreaterThan   ListFilterOp = ">"
	ListFilterGreaterEquals ListFilterOp = ">="
	ListFilterLessThan      ListFilterOp = "<"
	ListFilterLessEquals    ListFilterOp = "<="
)

// ListFilterType is the declared type of a filterable field.
type ListFilterType string

const (
	ListFilterString ListFilterType = "string"
	ListFilterBool   ListFilterType = "bool"
	ListFilterUint   ListFilterType = "uint"
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
		allowed := false
		for _, op := range declaration.Ops {
			if op == filter.Op {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: operator %q is not allowed on field %q", ErrInvalidListOption, filter.Op, filter.Field)
		}
		if err := validateFilterValue(filter, *declaration); err != nil {
			return err
		}
	}
	return nil
}

func validateFilterValue(filter ListFilter, field ListFilterField) error {
	switch field.Type {
	case ListFilterString:
		if _, ok := filter.Value.(string); !ok {
			return fmt.Errorf("%w: field %q expects a string", ErrInvalidListOption, field.Name)
		}
	case ListFilterBool:
		if _, ok := filter.Value.(bool); !ok {
			return fmt.Errorf("%w: field %q expects a bool", ErrInvalidListOption, field.Name)
		}
	case ListFilterUint:
		switch filter.Value.(type) {
		case int64, uint64, int, uint:
		default:
			return fmt.Errorf("%w: field %q expects an integer", ErrInvalidListOption, field.Name)
		}
	default:
		return fmt.Errorf("%w: field %q has an unsupported type", ErrInvalidListOption, field.Name)
	}
	return nil
}

// StringFilterOps is the operator set accepted for string fields.
func StringFilterOps() []ListFilterOp {
	return []ListFilterOp{ListFilterEquals, ListFilterNotEquals, ListFilterContains}
}

// stringFilterOps is kept for internal and backward compatibility.
func stringFilterOps() []ListFilterOp {
	return StringFilterOps()
}

// EqualityFilterOps is the operator set accepted for bool fields.
func EqualityFilterOps() []ListFilterOp {
	return []ListFilterOp{ListFilterEquals, ListFilterNotEquals}
}

// equalityFilterOps is kept for internal and backward compatibility.
func equalityFilterOps() []ListFilterOp {
	return EqualityFilterOps()
}

// NumericFilterOps is the operator set accepted for numeric fields.
func NumericFilterOps() []ListFilterOp {
	return []ListFilterOp{
		ListFilterEquals, ListFilterNotEquals,
		ListFilterGreaterThan, ListFilterGreaterEquals,
		ListFilterLessThan, ListFilterLessEquals,
	}
}

// numericFilterOps is kept for internal and backward compatibility.
func numericFilterOps() []ListFilterOp {
	return NumericFilterOps()
}

// ApplyListFilters applies validated ListFilters to a GORM query builder.
// It verifies field names against safe SQL identifier rules to protect against injection,
// and maps ListFilterOp comparisons (=, !=, >, >=, <, <=, contains) to parameterized SQL conditions.
func ApplyListFilters(db *gorm.DB, filters []ListFilter) (*gorm.DB, error) {
	if db == nil {
		return nil, errors.New("database instance is nil")
	}
	if len(filters) == 0 {
		return db, nil
	}

	query := db
	for _, filter := range filters {
		if err := validateFilterFieldName(filter.Field); err != nil {
			return nil, err
		}

		switch filter.Op {
		case ListFilterEquals:
			query = query.Where(filter.Field+" = ?", filter.Value)
		case ListFilterNotEquals:
			query = query.Where(filter.Field+" != ?", filter.Value)
		case ListFilterGreaterThan:
			query = query.Where(filter.Field+" > ?", filter.Value)
		case ListFilterGreaterEquals:
			query = query.Where(filter.Field+" >= ?", filter.Value)
		case ListFilterLessThan:
			query = query.Where(filter.Field+" < ?", filter.Value)
		case ListFilterLessEquals:
			query = query.Where(filter.Field+" <= ?", filter.Value)
		case ListFilterContains:
			valStr := fmt.Sprintf("%v", filter.Value)
			escaped := EscapeLikePattern(valStr)
			query = query.Where(filter.Field+" LIKE ? ESCAPE '\\'", "%"+escaped+"%")
		default:
			return nil, fmt.Errorf("%w: unsupported filter operator %q", ErrInvalidListOption, filter.Op)
		}
	}

	return query, nil
}

// EscapeLikePattern escapes SQL LIKE wildcards ('%', '_', '\') with a backslash.
func EscapeLikePattern(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func validateFilterFieldName(field string) error {
	if field == "" {
		return fmt.Errorf("%w: field name cannot be empty", ErrInvalidListOption)
	}
	for _, r := range field {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.') {
			return fmt.Errorf("%w: invalid field name %q", ErrInvalidListOption, field)
		}
	}
	return nil
}

// Page2LimitOffset converts page number and page size to limit and offset
// Parameters:
//
//	page: page number (starts at 1; if <= 0, automatically set to 1)
//	size: page size (if <= 0, automatically set to default of DefaultPageSize (20))
//
// Return values:
//
//	limit: items per page
//	offset: offset ((page-1)*size)
func Page2LimitOffset(page, size int) (limit, offset int) {
	// Handle invalid page number (ensure page >= 1)
	if page <= 0 {
		page = 1
	}
	// Handle invalid page size (set default value)
	if size <= 0 {
		size = DefaultPageSize
	}
	// Cap maximum page size (prevent querying too much data at once)
	if size > MaxPageSize {
		size = MaxPageSize
	}

	limit = size
	offset = (page - 1) * size
	return
}
