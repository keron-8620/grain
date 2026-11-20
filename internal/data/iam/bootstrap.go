package iam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"emperror.dev/errors"
	"gorm.io/gorm"
)

// LegacyDefaultAdminUsername is the account name that used to be seeded by
// sql/database.sql together with a publicly known password.
const LegacyDefaultAdminUsername = "admin"

// LegacyDefaultAdminPasswordHash is the bcrypt hash of the leaked seed
// password "Admin@123456". Accounts still using this hash are considered
// compromised: the service refuses to start and the bootstrap command resets
// them instead of creating a second account.
//
// #nosec G101 -- publicly known leaked hash, used only to detect and refuse the legacy default password
const LegacyDefaultAdminPasswordHash = "$2a$10$Z1dAGgfFqHnO5c1ZjKuO5.vD3VKS6XDK4ujaWPexdQfL2B54926oq"

// BootstrapAction describes what BootstrapAdmin did.
type BootstrapAction string

const (
	// BootstrapCreated means a new admin account was inserted.
	BootstrapCreated BootstrapAction = "created"
	// BootstrapReset means an existing account still used the leaked default
	// password and its password hash was replaced.
	BootstrapReset BootstrapAction = "reset"
)

// BootstrapAdmin creates the initial administrator account with the supplied
// bcrypt hash. It never overwrites an account that already has a non-default
// password: operators must use the regular password-change flow for that.
func BootstrapAdmin(ctx context.Context, gormDB *gorm.DB, username, passwordHash string) (BootstrapAction, error) {
	if gormDB == nil {
		return "", errors.New("bootstrap admin: database is required")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("bootstrap admin: username is required")
	}
	if strings.TrimSpace(passwordHash) == "" {
		return "", errors.New("bootstrap admin: password hash is required")
	}

	var action BootstrapAction
	err := gormDB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if !tx.Migrator().HasTable(&userPO{}) || !tx.Migrator().HasTable(&rolePO{}) {
			return errors.New("bootstrap admin: IAM tables are missing, run `grain -migrate` and import sql/database.sql first")
		}

		var role rolePO
		if roleErr := tx.Where("name = ?", "admin").Take(&role).Error; roleErr != nil {
			if errors.Is(roleErr, gorm.ErrRecordNotFound) {
				return errors.New("bootstrap admin: role \"admin\" does not exist, import sql/database.sql first")
			}
			return roleErr
		}

		var user userPO
		findErr := tx.Where("username = ?", username).Take(&user).Error
		switch {
		case findErr == nil:
			if user.Password != LegacyDefaultAdminPasswordHash {
				return fmt.Errorf("bootstrap admin: account %q already exists with a non-default password; use the password change API instead", username)
			}
			// The account still uses the leaked seed password: replace it and
			// bump the token version so previously issued sessions die.
			if updErr := tx.Model(&userPO{}).Where("id = ?", user.ID).Updates(map[string]any{
				"password":      passwordHash,
				"role_id":       role.ID,
				"is_active":     true,
				"token_version": gorm.Expr("token_version + 1"),
				"updated_at":    time.Now(),
			}).Error; updErr != nil {
				return updErr
			}
			action = BootstrapReset
			return nil
		case errors.Is(findErr, gorm.ErrRecordNotFound):
			created := userPO{
				Username: username,
				Password: passwordHash,
				IsActive: true,
				RoleID:   role.ID,
			}
			if createErr := tx.Create(&created).Error; createErr != nil {
				return createErr
			}
			action = BootstrapCreated
			return nil
		default:
			return findErr
		}
	})
	if err != nil {
		return "", err
	}
	return action, nil
}

// LegacyDefaultAdminAccounts lists accounts that still use the leaked default
// administrator password. A missing IAM table means "not bootstrapped yet" and
// yields an empty list so startup can continue to the migration path.
func LegacyDefaultAdminAccounts(ctx context.Context, gormDB *gorm.DB) ([]string, error) {
	if gormDB == nil {
		return nil, nil
	}
	if !gormDB.Migrator().HasTable(&userPO{}) {
		return nil, nil
	}

	var usernames []string
	if err := gormDB.WithContext(ctx).Model(&userPO{}).
		Where("password = ?", LegacyDefaultAdminPasswordHash).
		Order("id ASC").
		Pluck("username", &usernames).Error; err != nil {
		return nil, err
	}
	return usernames, nil
}

// HasLegacyDefaultAdmin reports whether any account still uses the leaked
// default administrator password.
func HasLegacyDefaultAdmin(ctx context.Context, gormDB *gorm.DB) (bool, error) {
	accounts, err := LegacyDefaultAdminAccounts(ctx, gormDB)
	if err != nil {
		return false, err
	}
	return len(accounts) > 0, nil
}
