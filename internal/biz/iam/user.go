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
	RoleID       uint64
	Role         *Role
	TokenVersion uint64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserUpdate describes a partial user profile update.
// A nil IsActive means the account status is left unchanged; otherwise the provided
// value is applied. This keeps patch semantics out of the User entity itself.
type UserUpdate struct {
	ID       uint64
	Username string
	Password string
	RoleID   uint64
	IsActive *bool
}

// Sanitize clears sensitive credential fields (such as the password hash) to avoid leaking them to upper layers
func (u *User) Sanitize() *User {
	if u != nil {
		u.Password = ""
	}
	return u
}

// UserRepo is the user repo interface contract
type UserRepo interface {
	Create(ctx context.Context, user *User) (*User, error)
	Update(ctx context.Context, user *User) (*User, error)
	Delete(ctx context.Context, id uint64) error
	FindByID(ctx context.Context, id uint64, preloads ...string) (*User, error)
	FindByUsername(ctx context.Context, username string, preloads ...string) (*User, error)
	// UsernameExists reports whether the username is taken, including by soft-deleted users.
	// Deleted usernames are never reusable.
	UsernameExists(ctx context.Context, username string) (bool, error)
	List(ctx context.Context, opts db.ListOptions) ([]User, int64, error)
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
	userRepo       UserRepo
	roleRepo       RoleRepo
	logger         *slog.Logger
	hasher         *cryptoutil.BcryptHasher
	auth           *AuthUseCase
	passwordPolicy PasswordPolicy
}

// NewUserUseCase creates a new UserUseCase instance.
// An optional PasswordPolicy controls password strength requirements.
func NewUserUseCase(userRepo UserRepo, roleRepo RoleRepo, logger *slog.Logger, policies ...PasswordPolicy) *UserUseCase {
	if logger == nil {
		logger = slog.Default()
	}
	policy := PasswordPolicy{}
	if len(policies) > 0 {
		policy = policies[0]
	}
	return &UserUseCase{
		userRepo:       userRepo,
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

	// Verify username uniqueness. Soft-deleted users reserve their username permanently.
	exists, err := uc.userRepo.UsernameExists(ctx, user.Username)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if exists {
		return nil, errorx.CodeDuplicatedKey.Error("用户名已存在")
	}

	hashedPassword, err := uc.hasher.HashString(rawPassword)
	if err != nil {
		uc.logger.ErrorContext(ctx, "failed to hash password", slog.Any("error", err))
		return nil, errorx.Wrap(err, errorx.CodeSystemError, "密码加密处理失败")
	}
	user.Password = hashedPassword

	created, err := uc.userRepo.Create(ctx, user)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	// Initialize token version cache
	_ = uc.userRepo.EnsureTokenVersionCache(ctx, created.ID, created.TokenVersion)

	ret := *created
	return ret.Sanitize(), nil
}

// Update updates an existing user profile, checks role validity, and revokes sessions
// if privileges, status, or credentials change. A nil IsActive leaves the status untouched.
func (uc *UserUseCase) Update(ctx context.Context, in UserUpdate) (*User, error) {
	if in.ID == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	oldUser, err := uc.userRepo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, errorx.FromDBError(err)
	}
	if oldUser == nil {
		return nil, errorx.CodeRecordNotFound.Error("用户不存在")
	}

	username := strings.TrimSpace(in.Username)
	if username != "" && username != oldUser.Username {
		// UsernameExists includes soft-deleted users, so deleted names stay reserved.
		exists, err := uc.userRepo.UsernameExists(ctx, username)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if exists {
			return nil, errorx.CodeDuplicatedKey.Error("用户名已被使用")
		}
	}
	if username == "" {
		username = oldUser.Username
	}

	roleID := oldUser.RoleID
	if in.RoleID > 0 && in.RoleID != oldUser.RoleID && uc.roleRepo != nil {
		role, err := uc.roleRepo.FindByID(ctx, in.RoleID)
		if err != nil {
			return nil, errorx.FromDBError(err)
		}
		if role == nil {
			return nil, errorx.CodeRecordNotFound.Error("指定角色不存在")
		}
		roleID = in.RoleID
	}

	isActive := oldUser.IsActive
	if in.IsActive != nil {
		isActive = *in.IsActive
	}

	passwordChanged := in.Password != ""
	hashedPassword := ""
	if passwordChanged {
		if err := uc.passwordPolicy.Validate(in.Password); err != nil {
			return nil, err
		}
		hashed, err := uc.hasher.HashString(in.Password)
		if err != nil {
			return nil, errorx.Wrap(err, errorx.CodeSystemError, "密码加密处理失败")
		}
		hashedPassword = hashed
	}

	updated, err := uc.userRepo.Update(ctx, &User{
		ID:       in.ID,
		Username: username,
		Password: hashedPassword,
		RoleID:   roleID,
		IsActive: isActive,
	})
	if err != nil {
		return nil, errorx.FromDBError(err)
	}

	if roleID != oldUser.RoleID || (oldUser.IsActive && !isActive) || passwordChanged {
		if revErr := uc.userRepo.IncrementTokenVersion(ctx, in.ID); revErr != nil {
			uc.logger.ErrorContext(ctx, "failed to revoke user sessions on profile update", slog.Uint64("user_id", in.ID), slog.Any("error", revErr))
			return nil, errorx.FromDBError(revErr)
		}
	}
	if passwordChanged {
		uc.clearLoginFailures(ctx, username)
	}

	ret := *updated
	return ret.Sanitize(), nil
}

func (uc *UserUseCase) clearLoginFailures(ctx context.Context, username string) {
	if username == "" {
		return
	}
	if err := uc.userRepo.ClearLoginFailures(ctx, username); err != nil {
		uc.logger.WarnContext(ctx, "failed to clear login failure counter", slog.String("username", username), slog.Any("error", err))
	}
}

// Delete soft-deletes a user by ID. Revoking the token version first invalidates
// outstanding refresh tokens; soft-deleted rows also disappear from all lookups.
func (uc *UserUseCase) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	user, err := uc.userRepo.FindByID(ctx, id)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if user == nil {
		return errorx.CodeRecordNotFound.Error("用户不存在")
	}

	// Must run before the soft delete: GORM filters deleted_at on updates, so the
	// token version can no longer be incremented afterwards.
	if err := uc.userRepo.IncrementTokenVersion(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}
	if err := uc.userRepo.Delete(ctx, id); err != nil {
		return errorx.FromDBError(err)
	}

	return nil
}

// Get finds a user by primary key ID and returns sanitized information.
func (uc *UserUseCase) Get(ctx context.Context, id uint64) (*User, error) {
	if id == 0 {
		return nil, errorx.CodeInvalidParam.Error("无效的用户ID")
	}

	user, err := uc.userRepo.FindByID(ctx, id, "Role")
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

	user, err := uc.userRepo.FindByUsername(ctx, cleanName, "Role")
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
func (uc *UserUseCase) List(ctx context.Context, opts db.ListOptions) ([]User, int64, error) {
	users, total, err := uc.userRepo.List(ctx, opts)
	if err != nil {
		return nil, 0, errorx.FromDBError(err)
	}
	res := make([]User, len(users))
	for i, u := range users {
		res[i] = *u.Sanitize()
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

	user, err := uc.userRepo.FindByID(ctx, userID)
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
	if _, err := uc.userRepo.Update(ctx, updateDo); err != nil {
		return errorx.FromDBError(err)
	}

	if revErr := uc.userRepo.IncrementTokenVersion(ctx, userID); revErr != nil {
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

	user, err := uc.userRepo.FindByID(ctx, userID)
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
	if _, err := uc.userRepo.Update(ctx, updateDo); err != nil {
		return errorx.FromDBError(err)
	}

	if revErr := uc.userRepo.IncrementTokenVersion(ctx, userID); revErr != nil {
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

	user, err := uc.userRepo.FindByID(ctx, userID)
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
	if _, err := uc.userRepo.Update(ctx, updateDo); err != nil {
		return errorx.FromDBError(err)
	}

	if !isActive {
		if revErr := uc.userRepo.IncrementTokenVersion(ctx, userID); revErr != nil {
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
	if err := uc.userRepo.IncrementTokenVersion(ctx, userID); err != nil {
		return errorx.FromDBError(err)
	}
	return nil
}

// RevokeRoleSessions revokes sessions for all users belonging to a role.
func (uc *UserUseCase) RevokeRoleSessions(ctx context.Context, roleID uint64) error {
	if roleID == 0 {
		return errorx.CodeInvalidParam.Error("无效的角色ID")
	}
	userIDs, err := uc.userRepo.ListIDsByRole(ctx, roleID)
	if err != nil {
		return errorx.FromDBError(err)
	}
	if len(userIDs) > 0 {
		if err := uc.userRepo.IncrementTokenVersionBatch(ctx, userIDs); err != nil {
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
