package job

import "grain/pkg/db"

// Filterable field → column mappings. These are the allowlists: a filter field or
// operator that is not declared here never reaches the SQL builder.
var (
	scriptFilterColumns = map[string]string{
		"id": "id", "name": "name", "descr": "descr", "param_desc": "param_desc",
		"project": "project", "label": "label", "language": "language",
		"status": "status", "username": "username",
	}
	scriptRecordFilterColumns = map[string]string{
		"id": "id", "trigger_type": "trigger_type", "status": "status", "exit_code": "exit_code",
		"username": "username", "script_id": "script_id", "host_id": "host_id",
		"work_dir": "work_dir", "timeout": "timeout", "log_name": "log_name",
	}
	scheduleFilterColumns = map[string]string{
		"id": "id", "name": "name", "is_enabled": "is_enabled", "username": "username",
		"script_id": "script_id", "host_id": "host_id", "timeout": "timeout",
		"is_retry": "is_retry", "max_retries": "max_retries",
	}
)

var (
	scriptOrderColumns = db.NewColumnSet(
		"id", "name", "project", "label", "language", "status", "username",
		"created_at", "updated_at",
	)
	scriptRecordOrderColumns = db.NewColumnSet(
		"id", "trigger_type", "status", "exit_code", "username", "script_id", "host_id",
		"timeout", "created_at", "updated_at",
	)
	scheduleOrderColumns = db.NewColumnSet(
		"id", "name", "is_enabled", "username", "script_id", "host_id",
		"timeout", "is_retry", "max_retries", "created_at", "updated_at",
	)
)
