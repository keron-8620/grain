package db

import (
	"fmt"
	"reflect"
	"strings"

	"emperror.dev/errors"
	"gorm.io/gorm"

	"grain/pkg/db/filter"
)

// ErrInvalidListOption is returned when a client-supplied list option (such as filter or order_by)
// is malformed or references a field outside the allowlist.
var ErrInvalidListOption = filter.ErrInvalidListOption

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
type ListFilterOp = filter.ListFilterOp

const (
	ListFilterEquals        = filter.ListFilterEquals
	ListFilterNotEquals     = filter.ListFilterNotEquals
	ListFilterContains      = filter.ListFilterContains
	ListFilterGreaterThan   = filter.ListFilterGreaterThan
	ListFilterGreaterEquals = filter.ListFilterGreaterEquals
	ListFilterLessThan      = filter.ListFilterLessThan
	ListFilterLessEquals    = filter.ListFilterLessEquals
	ListFilterIn            = filter.ListFilterIn
	ListFilterNotIn         = filter.ListFilterNotIn
	ListFilterIsNull        = filter.ListFilterIsNull
	ListFilterIsNotNull     = filter.ListFilterIsNotNull
)

// ListFilterType is the declared type of a filterable field.
type ListFilterType = filter.ListFilterType

const (
	ListFilterString = filter.ListFilterString
	ListFilterBool   = filter.ListFilterBool
	ListFilterUint   = filter.ListFilterUint
	ListFilterInt    = filter.ListFilterInt
	ListFilterFloat  = filter.ListFilterFloat
	ListFilterTime   = filter.ListFilterTime
)

// ListFilterField declares a filterable field and the operators it accepts.
// Exported per resource so the transport layer can type-check AIP filters.
type ListFilterField = filter.ListFilterField

// ListFilter is a single, already type-checked filter comparison.
type ListFilter = filter.ListFilter

// ListOptions is the shared pagination, filtering, and ordering input for repository
// list queries. Storage-layer details such as preloads and column allowlists stay in
// QueryParams and must not leak into the biz-layer contract.
type ListOptions struct {
	Offset   int
	PageSize int
	Filters  []ListFilter
	OrderBy  string
}

// Normalize applies the default page size and validates the pagination bounds.
func (o *ListOptions) Normalize() error {
	if o.PageSize <= 0 {
		o.PageSize = DefaultPageSize
	}
	return ValidateListOptions(o.Offset, o.PageSize)
}

// ValidateListFilters re-validates parsed filters against the resource declarations
// (defense in depth: the storage layer must never receive an undeclared field or operator).
var ValidateListFilters = filter.ValidateListFilters

// StringFilterOps is the operator set accepted for string fields.
var StringFilterOps = filter.StringFilterOps

// stringFilterOps is kept for internal and backward compatibility.
func stringFilterOps() []ListFilterOp {
	return StringFilterOps()
}

// EqualityFilterOps is the operator set accepted for bool fields.
var EqualityFilterOps = filter.EqualityFilterOps

// equalityFilterOps is kept for internal and backward compatibility.
func equalityFilterOps() []ListFilterOp {
	return EqualityFilterOps()
}

// NumericFilterOps is the operator set accepted for numeric fields.
var NumericFilterOps = filter.NumericFilterOps

// numericFilterOps is kept for internal and backward compatibility.
func numericFilterOps() []ListFilterOp {
	return NumericFilterOps()
}

// IntFilterOps is the operator set accepted for signed integer fields.
var IntFilterOps = filter.IntFilterOps

// FloatFilterOps is the operator set accepted for floating-point fields.
var FloatFilterOps = filter.FloatFilterOps

// TimeFilterOps is the operator set accepted for time/timestamp fields.
var TimeFilterOps = filter.TimeFilterOps

// SetFilterOps returns the set membership operators (in, not in).
var SetFilterOps = filter.SetFilterOps

// NullFilterOps returns the nullability check operators (is null, is not null).
var NullFilterOps = filter.NullFilterOps

// LikeEscapeChar is the dialect-neutral SQL LIKE escape character ('!').
// Using '!' instead of '\' avoids dialect-specific string literal backslash escaping
// differences across MySQL (NO_BACKSLASH_ESCAPES), PostgreSQL/OpenGauss
// (standard_conforming_strings), SQLite, and SQL Server.
const LikeEscapeChar = '!'

const likeEscapeClause = " ESCAPE '!'"

// applyListFilters applies validated ListFilters to a GORM query builder.
// It verifies field names against safe SQL identifier rules to protect against injection,
// and maps ListFilterOp comparisons (=, !=, >, >=, <, <=, contains, in, not in, is null, is not null)
// to parameterized SQL conditions.
func applyListFilters(db *gorm.DB, filters []ListFilter) (*gorm.DB, error) {
	return applyListFiltersWithOptions(db, filters, nil, nil)
}

func applyListFiltersWithOptions(
	db *gorm.DB,
	filters []ListFilter,
	allowed map[string]struct{},
	columnMap map[string]string,
) (*gorm.DB, error) {
	if db == nil {
		return nil, errors.New("database instance is nil")
	}
	if len(filters) == 0 {
		return db, nil
	}

	query := db
	for _, filter := range filters {
		col, err := resolveFilterColumn(filter.Field, allowed, columnMap)
		if err != nil {
			return nil, err
		}

		switch filter.Op {
		case ListFilterEquals:
			query = query.Where(col+" = ?", filter.Value)
		case ListFilterNotEquals:
			query = query.Where(col+" != ?", filter.Value)
		case ListFilterGreaterThan:
			query = query.Where(col+" > ?", filter.Value)
		case ListFilterGreaterEquals:
			query = query.Where(col+" >= ?", filter.Value)
		case ListFilterLessThan:
			query = query.Where(col+" < ?", filter.Value)
		case ListFilterLessEquals:
			query = query.Where(col+" <= ?", filter.Value)
		case ListFilterContains:
			valStr, ok := filter.Value.(string)
			if !ok {
				return nil, fmt.Errorf("%w: field %q with %q operator expects a string", ErrInvalidListOption, filter.Field, filter.Op)
			}
			escaped := EscapeLikePattern(valStr)
			query = query.Where(col+" LIKE ?"+likeEscapeClause, "%"+escaped+"%")
		case ListFilterIn:
			if err := validateNonEmptySliceValue(filter.Field, filter.Op, filter.Value); err != nil {
				return nil, err
			}
			query = query.Where(col+" IN ?", filter.Value)
		case ListFilterNotIn:
			if err := validateNonEmptySliceValue(filter.Field, filter.Op, filter.Value); err != nil {
				return nil, err
			}
			query = query.Where(col+" NOT IN ?", filter.Value)
		case ListFilterIsNull:
			query = query.Where(col + " IS NULL")
		case ListFilterIsNotNull:
			query = query.Where(col + " IS NOT NULL")
		default:
			return nil, fmt.Errorf("%w: unsupported filter operator %q", ErrInvalidListOption, filter.Op)
		}
	}

	return query, nil
}

func resolveFilterColumn(field string, allowed map[string]struct{}, columnMap map[string]string) (string, error) {
	if field == "" {
		return "", fmt.Errorf("%w: field name cannot be empty", ErrInvalidListOption)
	}

	target := field
	if columnMap != nil {
		mapped, ok := columnMap[field]
		if !ok {
			mapped, ok = columnMap[strings.ToLower(field)]
		}
		if !ok {
			return "", fmt.Errorf("%w: field %q is not filterable", ErrInvalidListOption, field)
		}
		target = mapped
	}

	if err := validateFilterFieldName(target); err != nil {
		return "", err
	}

	if allowed != nil {
		lowerCol := strings.ToLower(target)
		matched := false
		if _, ok := allowed[lowerCol]; ok {
			matched = true
		} else if idx := strings.LastIndex(lowerCol, "."); idx != -1 {
			if _, ok := allowed[lowerCol[idx+1:]]; ok {
				matched = true
			}
		}
		if !matched {
			return "", fmt.Errorf("%w: field %q is not filterable", ErrInvalidListOption, field)
		}
	}

	return target, nil
}

func validateNonEmptySliceValue(field string, op ListFilterOp, val any) error {
	if val == nil {
		return fmt.Errorf("%w: field %q with %q operator expects a non-empty slice", ErrInvalidListOption, field, op)
	}
	rv := reflect.ValueOf(val)
	if (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) || rv.Len() == 0 {
		return fmt.Errorf("%w: field %q with %q operator expects a non-empty slice", ErrInvalidListOption, field, op)
	}
	return nil
}

// EscapeLikePattern escapes SQL LIKE wildcards ('%', '_') and the escape character ('!') with '!'.
func EscapeLikePattern(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '%', '_', LikeEscapeChar:
			b.WriteByte(LikeEscapeChar)
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
	if err := validateSQLIdentifier(field); err != nil {
		return fmt.Errorf("%w: invalid field name %q: %v", ErrInvalidListOption, field, err)
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

// ValidateListOptions enforces the storage-side list bounds (defense in depth: the biz layer
// validates too, but repos must never accept an unbounded query).
func ValidateListOptions(offset, pageSize int) error {
	if offset < 0 {
		return fmt.Errorf("%w: offset must be non-negative, got %d", ErrInvalidListOption, offset)
	}
	if pageSize <= 0 {
		return fmt.Errorf("%w: page_size must be positive, got %d", ErrInvalidListOption, pageSize)
	}
	if pageSize > MaxPageSize {
		return fmt.Errorf("%w: page_size cannot exceed %d, got %d", ErrInvalidListOption, MaxPageSize, pageSize)
	}
	return nil
}

func NewColumnSet(columns ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		set[strings.ToLower(column)] = struct{}{}
	}
	return set
}

// SanitizeOrderBy validates a client-supplied order_by expression against an allowlist of
// columns. Accepted per clause: "col", "col asc", "col desc" (case-insensitive) and a leading
// "-" for descending; clauses are comma-separated. Anything else (extra tokens, subqueries,
// functions, unknown columns) is rejected with ErrInvalidListOption.
func SanitizeOrderBy(raw string, allowed map[string]struct{}) (string, error) {
	expr := strings.TrimSpace(raw)
	if expr == "" {
		return "", nil
	}
	clauses := make([]string, 0, strings.Count(expr, ",")+1)
	for part := range strings.SplitSeq(expr, ",") {
		clause, err := sanitizeOrderClause(part, allowed)
		if err != nil {
			return "", err
		}
		clauses = append(clauses, clause)
	}
	return strings.Join(clauses, ", "), nil
}

func sanitizeOrderClause(raw string, allowed map[string]struct{}) (string, error) {
	expr := strings.TrimSpace(raw)
	if expr == "" {
		return "", fmt.Errorf("%w: empty order column", ErrInvalidListOption)
	}

	descending := false
	if strings.HasPrefix(expr, "-") {
		descending = true
		expr = strings.TrimSpace(expr[1:])
		if expr == "" {
			return "", fmt.Errorf("%w: empty order column", ErrInvalidListOption)
		}
	}

	fields := strings.Fields(expr)
	if len(fields) > 2 {
		return "", fmt.Errorf("%w: unexpected tokens in order_by", ErrInvalidListOption)
	}

	rawCol := fields[0]
	if err := validateSQLIdentifier(rawCol); err != nil {
		return "", fmt.Errorf("%w: invalid order_by column %q: %v", ErrInvalidListOption, rawCol, err)
	}

	column := strings.ToLower(rawCol)
	if allowed != nil {
		matched := false
		if _, ok := allowed[column]; ok {
			matched = true
		} else if idx := strings.LastIndex(column, "."); idx != -1 {
			if _, ok := allowed[column[idx+1:]]; ok {
				matched = true
			}
		}
		if !matched {
			return "", fmt.Errorf("%w: column %q is not sortable", ErrInvalidListOption, rawCol)
		}
	}

	if len(fields) == 2 {
		if descending {
			return "", fmt.Errorf("%w: conflicting order direction", ErrInvalidListOption)
		}
		switch strings.ToLower(fields[1]) {
		case "asc":
			descending = false
		case "desc":
			descending = true
		default:
			return "", fmt.Errorf("%w: invalid order direction %q", ErrInvalidListOption, fields[1])
		}
	}

	direction := "ASC"
	if descending {
		direction = "DESC"
	}
	return column + " " + direction, nil
}
