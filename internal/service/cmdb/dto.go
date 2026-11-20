package cmdb

import (
	"time"

	biz "grain/internal/biz/cmdb"
	"grain/internal/service/common"
	"grain/pkg/remote"
)

// HostResp is the public representation of a managed host.
type HostResp struct {
	ID       uint64 `json:"id" example:"1"`
	Name     string `json:"name" example:"web-01"`
	Label    string `json:"label" example:"prod"`
	HostIP   string `json:"host_ip" example:"10.0.0.10"`
	HostPort uint16 `json:"host_port" example:"22"`
	HostUser string `json:"host_user" example:"root"`
	Protocol string `json:"protocol" example:"ssh"`
	PyPath   string `json:"py_path" example:"/usr/bin/python3"`
	Remark   string `json:"remark" example:"web server"`
	OSType   string `json:"os_type" example:"linux"`
	// SSHHostKeyFingerprint identifies the pinned SSH host key; empty when the
	// host was created without SSH onboarding.
	SSHHostKeyFingerprint string    `json:"ssh_host_key_fingerprint" example:"SHA256:abc..."`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// HostPageResult is a paginated host list.
type HostPageResult struct {
	List  []HostResp `json:"list"`
	Total int64      `json:"total" example:"1"`
}

// CreateHostReq is the request body for creating a host.
type CreateHostReq struct {
	Name     string `json:"name" binding:"required,min=1,max=50" example:"web-01"`
	Label    string `json:"label" binding:"omitempty,max=50" example:"prod"`
	HostIP   string `json:"host_ip" binding:"required,max=108" example:"10.0.0.10"`
	HostPort uint16 `json:"host_port" example:"22"`
	HostUser string `json:"host_user" binding:"required,max=50" example:"root"`
	Protocol string `json:"protocol" binding:"omitempty,oneof=ssh winrm" example:"ssh"`
	PyPath   string `json:"py_path" binding:"omitempty,max=254" example:"/usr/bin/python3"`
	Remark   string `json:"remark" binding:"omitempty,max=254" example:"web server"`
	OSType   string `json:"os_type" binding:"omitempty,oneof=linux windows" example:"linux"`
}

// UpdateHostReq is the request body for replacing a host. All connection
// fields are taken from the request; omitted optional fields are cleared.
type UpdateHostReq struct {
	Name     string `json:"name" binding:"required,min=1,max=50" example:"web-01"`
	Label    string `json:"label" binding:"omitempty,max=50" example:"prod"`
	HostIP   string `json:"host_ip" binding:"required,max=108" example:"10.0.0.10"`
	HostPort uint16 `json:"host_port" example:"22"`
	HostUser string `json:"host_user" binding:"required,max=50" example:"root"`
	Protocol string `json:"protocol" binding:"omitempty,oneof=ssh winrm" example:"ssh"`
	PyPath   string `json:"py_path" binding:"omitempty,max=254" example:"/usr/bin/python3"`
	Remark   string `json:"remark" binding:"omitempty,max=254" example:"web server"`
	OSType   string `json:"os_type" binding:"omitempty,oneof=linux windows" example:"linux"`
}

// ListHostReq is the query string for listing hosts.
type ListHostReq struct {
	common.PaginationReq
	Name     string `form:"name" example:"web"`
	Label    string `form:"label" example:"prod"`
	HostIP   string `form:"host_ip" example:"10.0.0."`
	Protocol string `form:"protocol" binding:"omitempty,oneof=ssh winrm" example:"ssh"`
	OSType   string `form:"os_type" binding:"omitempty,oneof=linux windows" example:"linux"`
}

func toHostResp(h *biz.Host) HostResp {
	return HostResp{
		ID:                    h.ID,
		Name:                  h.Name,
		Label:                 h.Label,
		HostIP:                h.HostIP,
		HostPort:              h.HostPort,
		HostUser:              h.HostUser,
		Protocol:              h.Protocol,
		PyPath:                h.PyPath,
		Remark:                h.Remark,
		OSType:                h.OSType,
		SSHHostKeyFingerprint: hostKeyFingerprint(h.HostKey),
		CreatedAt:             h.CreatedAt,
		UpdatedAt:             h.UpdatedAt,
	}
}

func hostKeyFingerprint(raw string) string {
	key, err := remote.ParseHostKey(raw)
	if err != nil {
		return ""
	}
	return remote.HostKeyFingerprint(key)
}

func toHostRespList(hosts []biz.Host) []HostResp {
	res := make([]HostResp, 0, len(hosts))
	for i := range hosts {
		res = append(res, toHostResp(&hosts[i]))
	}
	return res
}
