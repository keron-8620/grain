package iam

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"grain/pkg/cryptoutil"
	"grain/pkg/db"
	"grain/pkg/errorx"
)

// User is the user domain object (Domain Object - DO)
type User struct {
	ID           uint64
	Username     string
	Password     string
	IsActive     bool
	IsActiveSet  bool
	RoleID       uint64
	Role         *Role
	TokenVersion uint64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Sanitize clears sensitive credential fields (such as the password hash) to avoid leaking them to upper layers
func (u *User) Sanitize() *User {
	if u != nil {
		u.Password = ""
	}
	return u
}

// UserListOptions are the user list query options
type UserListOptions struct {
	Offset   int
	PageSize int
	Filters  []db.ListFilter
	OrderBy  string
}

// UserRepo is the user repo interface contract
type UserRepo interface {
	Create(ctx context.Context, user *User) (*User, error)
	Update(ctx context.Context, user *User) (*User, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*User, error)
	FindByUsername(ctx context.Context, username string, preloads ...string) (*User, error)
	List(ctx context.Context, opts UserListOptions) ([]*User, int64, error)
	ListIDsByRole(ctx context.Context, roleID uint64) ([]uint64, error)

	// Token version and session revocation
	IncrementTokenVersion(ctx context.Context, userID uint64) error
	IncrementTokenVersionBatch(ctx context.Context, userIDs []uint64) error
	GetTokenVersion(ctx context.Context, userID uint64) (uint64, error)
	EnsureTokenVersionCache(ctx context.Context, userID uint64, version uint64) error
	ConsumeRefreshToken(ctx context.Context, jti string, ttl time.Duration) (bool, error)
	RotateRefreshTokenFamily(ctx context.Context, familyID, oldJTI, newJTI string, userID uint64, ttl time.Duration) (RotateFamilyResult, error)

	// Login failure counters back the account lockout policy.
	GetLoginFailure(ctx context.Context, username string) (int64, error)
	IncrementLoginFailure(ctx context.Context, username string, ttl time.Duration) (int64, error)
	ClearLoginFailures(ctx context.Context, username string) error
}

// RotateFamilyResult represents the outcome of a token family rotation operation.
type RotateFamilyResult int

const (
	RotateFamilySuccess RotateFamilyResult = iota
	RotateFamilyCompromised
	RotateFamilyFailed
)

// UserUseCase handles user management, password lifecycle, and account session controls.
type UserUseCase struct {
	repo           UserRepo
	roleRepo       RoleRepo
	logger         *slog.Logger
	hasher         *cryptoutil.BcryptHasher
	auth           *AuthUseCase
	passwordPolicy PasswordPolicy
}

// NewUserUseCase creates a new UserUseCase instance.
// An optional PasswordPolicy controls password strength requirements.
func NewUserUseCase(repo UserRepo, roleRepo RoleRepo, logger *slog.Logger, policies ...PasswordPolicy) *UserUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	policy := PasswordPolicy{}
	if len(policies) > 0 {
		policy = policies[0]
	}
	return &UserUseCase{
		repo:           repo,
		roleRepo:       roleRepo,
		logger:         logger,
		hasher:         cryptoutil.NewBcryptHasher(0),
		passwordPolicy: policy,
	}
}

// SetAuthUseCase attaches the authentication use case to allow login/logout delegation.
func (uc *UserUseCase) SetAuthUseCase(auth *AuthUseCase) {
	uc.auth = auth
}

// Create creates a new user, hashes their raw password, and initializes token version cache.
func (uc *UserUseCase) Create(ctx context.Context, user *User, rawPassword string) (*User, error) {
	if user == nil {
		return nil, errorx.CodeInvalidParam.Error("用户信息不能为空")
	}

	username := strings.TrimSpace(user.Username)
	if username == "" {
		return nil, errorx.CodeMissingParam.Error("用户名不能为空")
	}
	if err := uc.passwordPolicy.Validate(rawPassword); err != nil {
		return nil, err
	}
	if user.RoleID == 0 {
		return nil, errorx.CodeMissingParam.Error("用户必须分配角色")
	}
	user.Username = username

	// Verify the associated role exists
	if uc.roleRepo != nil {
		role, err := uc.roleRepo.FindByID(ctx, user.RoleID)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if role == nil {
			return nil, errorx.CodeRecordNotFound.Error("指定角色不存在")
		}
	}

	// Verify username uniqueness
	existing, err := uc.repo.FindByUsername(ctx, user.Username)
	if err != nil && !errorx.IsRecordNotFound(err) {
		return nil, errorx.FromDBError(err)
	}
	if existing != nil {
		return nil, errorx.CodeDuplicatedKey.Error("用户名已存在")
	}

	hashedPassword, err := uc.hasher.HashString(rawPassword)
	if err != nil {
		uc.logger.ErrorContext(ctx, "failed to hash password", slog.Any("error", err))
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "密码加密处理失败")
	}
	user.Password = hashedPassword

	created, err := uc.repo.Create(ctx, user)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	// Initialize token version cache
	_ = uc.repo.EnsureTokenVersionCache(ctx, created.ID, created.TokenVersion)

	ret := *created
	return ret.Sanitize(), nil
}

// Update updates an existing user, checks role validity, and revokes sessions if privileges or status change.
func (uc *UserUseCase) Update(ctx context.Context, user *User) (*User, error) {
	if user == nil || user.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	oldUser, err := uc.repo.FindByID(ctx, user.ID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldUser == nil {
		return nil, errorx.CodeRecordNotFound.Error("用户不存在")
	}

	username := strings.TrimSpace(user.Username)
	if username != "" && username != oldUser.Username {
		existing, err := uc.repo.FindByUsername(ctx, username)
		if err != nil && !errorx.IsRecordNotFound(err) {
			return nil, errorx.FromDBError(err)
		}
		if existing != nil && existing.ID != user.ID {
			return nil, errorx.CodeDuplicatedKey.Error("用户名已被使用")
		}
	}
	if username == "" {
		user.Username = oldUser.Username
	} else {
		user.Username = username
	}

	if user.RoleID > 0 && user.RoleID != oldUser.RoleID && uc.roleRepo != nil {
		role, err := uc.roleRepo.FindByID(ctx, user.RoleID)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if role == nil {
			return nil, errorx.CodeRecordNotFound.Error("指定角色不存在")
		}
	} else {
		user.RoleID = oldUser.RoleID
	}

	if !user.IsActiveSet && (username != "" || user.RoleID > 0 || user.Password != "") {
		user.IsActive = oldUser.IsActive
	}

	passwordChanged := user.Password != ""
	if passwordChanged {
		if err := uc.passwordPolicy.Validate(user.Password); err != nil {
			return nil, err
		}
		hashed, err := uc.hasher.HashString(user.Password)
		if err != nil {
			return nil, errorx.Wrap(err, errorx.CodeSystemError, "密码加密处理失败")
		}
		user.Password = hashed
	}

	updated, err := uc.repo.Update(ctx, user)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	if user.RoleID != oldUser.RoleID || (oldUser.IsActive && !user.IsActive) || passwordChanged {
		if revErr := uc.repo.IncrementTokenVersion(ctx, user.ID); revErr != nil {
			uc.logger.ErrorContext(ctx, "failed to revoke user sessions on profile update", slog.Uint64("user_id", user.ID), slog.Any("error", revErr))
			return nil, errorx.FromDBError(revErr)
		}
	}
	if passwordChanged {
		uc.clearLoginFailures(ctx, user.Username)
	}

	ret := *updated
	return ret.Sanitize(), nil
}

func (uc *UserUseCase) clearLoginFailures(ctx context.Context, username string) {
	if username == "" {
		return
	}
	if err := uc.repo.ClearLoginFailures(ctx, username); err != nil {
		uc.logger.WarnContext(ctx, "failed to clear login failure counter", slog.String("username", username), slog.Any("error", err))
	}
}

// Delete deletes a user by ID.
func (uc *UserUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	user, err := uc.repo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if user == nil {
		return errorx.CodeRecordNotFound.Error("用户不存在")
	}

	if err := uc.repo.Delete(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}

	return nil
}

// Get finds a user by primary key ID and returns sanitized information.
func (uc *UserUseCase) Get(ctx context.Context, id uint64) (*User, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	user, err := uc.repo.FindByID(ctx, id, "Role")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if user == nil {
		return nil, errorx.CodeRecordNotFound.Error("用户不存在")
	}

	ret := *user
	return ret.Sanitize(), nil
}

// GetByUsername finds a user by username and returns sanitized information.
func (uc *UserUseCase) GetByUsername(ctx context.Context, username string) (*User, error) {
	cleanName := strings.TrimSpace(username)
	if cleanName == "" {
		return nil, errorx.CodeMissingParam.Error("用户名不能为空")
	}

	user, err := uc.repo.FindByUsername(ctx, cleanName, "Role")
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if user == nil {
		return nil, errorx.CodeRecordNotFound.Error("用户不存在")
	}

	ret := *user
	return ret.Sanitize(), nil
}

// List lists users with conditions and returns sanitized results.
func (uc *UserUseCase) List(ctx context.Context, opts UserListOptions) ([]*User, int64, error) {
	users, total, err := uc.repo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	res := make([]*User, len(users))
	for i, u := range users {
		if u != nil {
			cp := *u
			res[i] = cp.Sanitize()
		}
	}
	return res, total, nil
}

// ChangePassword verifies the old password, hashes the new password, and revokes all active sessions.
func (uc *UserUseCase) ChangePassword(ctx context.Context, userID uint64, oldPassword, newPassword string) error {
	if userID == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}
	if oldPassword == "" || newPassword == "" {
		return errorx.CodeMissingParam.Error("原密码和新密码不能为空")
	}
	if err := uc.passwordPolicy.Validate(newPassword); err != nil {
		return err
	}

	user, err := uc.repo.FindByID(ctx, userID)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if user == nil {
		return errorx.CodeRecordNotFound.Error("用户不存在")
	}

	valid, err := uc.hasher.VerifyString(oldPassword, user.Password)
	if err != nil || !valid {
		return errorx.CodeAuthFailed.Error("原密码错误")
	}

	hashedPassword, err := uc.hasher.HashString(newPassword)
	if err != nil {
		return errorx.Wrap(err, errorx.CodeSystemError, "密码加密处理失败")
	}

	updateDo := &User{
		ID:       userID,
		Username: user.Username,
		Password: hashedPassword,
		RoleID:   user.RoleID,
		IsActive: user.IsActive,
	}
	if _, err := uc.repo.Update(ctx, updateDo); err != nil {
		return errorx.FromDBError(err)
	}

	if revErr := uc.repo.IncrementTokenVersion(ctx, userID); revErr != nil {
		return errorx.FromDBError(revErr)
	}
	uc.clearLoginFailures(ctx, user.Username)
	return nil
}

// ResetPassword resets a user's password directly (administrative operation) and revokes their active sessions.
func (uc *UserUseCase) ResetPassword(ctx context.Context, userID uint64, newPassword string) error {
	if userID == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}
	if err := uc.passwordPolicy.Validate(newPassword); err != nil {
		return err
	}

	user, err := uc.repo.FindByID(ctx, userID)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if user == nil {
		return errorx.CodeRecordNotFound.Error("用户不存在")
	}

	hashedPassword, err := uc.hasher.HashString(newPassword)
	if err != nil {
		return errorx.Wrap(err, errorx.CodeSystemError, "密码加密处理失败")
	}

	updateDo := &User{
		ID:       userID,
		Username: user.Username,
		Password: hashedPassword,
		RoleID:   user.RoleID,
		IsActive: user.IsActive,
	}
	if _, err := uc.repo.Update(ctx, updateDo); err != nil {
		return errorx.FromDBError(err)
	}

	if revErr := uc.repo.IncrementTokenVersion(ctx, userID); revErr != nil {
		return errorx.FromDBError(revErr)
	}
	uc.clearLoginFailures(ctx, user.Username)

	return nil
}

// UpdateStatus toggles a user's active status and revokes sessions if deactivated.
func (uc *UserUseCase) UpdateStatus(ctx context.Context, userID uint64, isActive bool) error {
	if userID == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	user, err := uc.repo.FindByID(ctx, userID)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if user == nil {
		return errorx.CodeRecordNotFound.Error("用户不存在")
	}

	if user.IsActive == isActive {
		return nil
	}

	updateDo := &User{
		ID:       userID,
		Username: user.Username,
		RoleID:   user.RoleID,
		IsActive: isActive,
	}
	if _, err := uc.repo.Update(ctx, updateDo); err != nil {
		return errorx.FromDBError(err)
	}

	if !isActive {
		if revErr := uc.repo.IncrementTokenVersion(ctx, userID); revErr != nil {
			return errorx.FromDBError(revErr)
		}
	} else {
		uc.clearLoginFailures(ctx, user.Username)
	}

	return nil
}

// RevokeUserSessions revokes all active sessions for a user by incrementing their token version.
func (uc *UserUseCase) RevokeUserSessions(ctx context.Context, userID uint64) error {
	if userID == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}
	if err := uc.repo.IncrementTokenVersion(ctx, userID); err != nil {
		return errorx.FromDBError(err)
	}
	return nil
}

// RevokeRoleSessions revokes sessions for all users belonging to a role.
func (uc *UserUseCase) RevokeRoleSessions(ctx context.Context, roleID uint64) error {
	if roleID == 0 {
		return errorx.CodeInvalidParam.Error("无效的角色ID")
	}
	userIDs, err := uc.repo.ListIDsByRole(ctx, roleID)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if len(userIDs) > 0 {
		if err := uc.repo.IncrementTokenVersionBatch(ctx, userIDs); err != nil {
			return errorx.FromDBError(err)
		}
	}
	return nil
}

// Login delegates user authentication to the attached AuthUseCase.
func (uc *UserUseCase) Login(ctx context.Context, username, password string) (*LoginResult, error) {
	if uc.auth == nil {
		return nil, errorx.CodeNotImplemented.Error("未配置认证用例")
	}
	return uc.auth.Login(ctx, username, password)
}

// RefreshToken delegates refresh token rotation to the attached AuthUseCase.
func (uc *UserUseCase) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	if uc.auth == nil {
		return nil, errorx.CodeNotImplemented.Error("未配置认证用例")
	}
	return uc.auth.RefreshToken(ctx, refreshToken)
}

// Logout delegates user logout to the attached AuthUseCase.
func (uc *UserUseCase) Logout(ctx context.Context, userID uint64, jti string, ttl ...time.Duration) error {
	if uc.auth == nil {
		return errorx.CodeNotImplemented.Error("未配置认证用例")
	}
	return uc.auth.Logout(ctx, userID, jti, ttl...)
}
