package cmdb

import "grain/pkg/db"

// Filterable field → column mappings. These are the allowlists: a filter field or
// operator that is not declared here never reaches the SQL builder.
var (
	hostFilterColumns = map[string]string{
		"id": "id", "name": "name", "label": "label",
		"host_ip": "host_ip", "host_port": "host_port", "host_user": "host_user",
		"protocol": "protocol", "py_path": "py_path", "remark": "remark", "os_type": "os_type",
	}
)

var (
	hostOrderColumns = db.NewColumnSet(
		"id", "name", "label", "host_ip", "host_port", "host_user",
		"protocol", "os_type", "created_at", "updated_at",
	)
)
