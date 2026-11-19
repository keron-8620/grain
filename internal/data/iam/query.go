package iam

import "grain/pkg/db"

// Filterable field → column mappings. These are the allowlists: a filter field or operator
// that is not declared here never reaches the SQL builder.
var (
	userFilterColumns = map[string]string{
		"id": "id", "username": "username", "is_active": "is_active", "role_id": "role_id", "token_version": "token_version",
	}
	roleFilterColumns = map[string]string{
		"id": "id", "name": "name", "descr": "descr",
	}
	menuFilterColumns = map[string]string{
		"id": "id", "path": "path", "component": "component", "name": "name",
		"is_active": "is_active", "parent_id": "parent_id", "sort": "sort", "descr": "descr",
	}
	buttonFilterColumns = map[string]string{
		"id": "id", "name": "name", "sort": "sort", "is_active": "is_active", "menu_id": "menu_id", "descr": "descr",
	}
	apiFilterColumns = map[string]string{
		"id": "id", "url": "url", "method": "method", "label": "label", "descr": "descr",
	}
)

var (
	userOrderColumns   = db.NewColumnSet("id", "username", "is_active", "role_id", "token_version", "created_at", "updated_at")
	roleOrderColumns   = db.NewColumnSet("id", "name", "created_at", "updated_at")
	menuOrderColumns   = db.NewColumnSet("id", "path", "component", "name", "sort", "is_active", "parent_id", "created_at", "updated_at")
	buttonOrderColumns = db.NewColumnSet("id", "name", "sort", "is_active", "menu_id", "created_at", "updated_at")
	apiOrderColumns    = db.NewColumnSet("id", "url", "method", "label", "created_at", "updated_at")
)
