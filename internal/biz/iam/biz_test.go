package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBiz(t *testing.T) {
	apiRepo := newMockApiRepo()
	buttonRepo := newMockButtonRepo()
	menuRepo := newMockMenuRepo()
	roleRepo := newMockRoleRepo()
	userRepo := newMockUserRepo()

	apiUC := NewApiUseCase(apiRepo, nil)
	btnUC := NewButtonUseCase(buttonRepo, menuRepo, nil)
	menuUC := NewMenuUseCase(menuRepo, nil, buttonRepo)
	roleUC := NewRoleUseCase(roleRepo, userRepo, nil)
	userUC := NewUserUseCase(userRepo, roleRepo, nil)

	tokenMgr, err := NewTokenManager(TokenConfig{})
	require.NoError(t, err)

	authUC := NewAuthUseCase(userRepo, roleRepo, tokenMgr, nil)

	biz := NewBiz(userUC, roleUC, menuUC, btnUC, apiUC, authUC)
	assert.NotNil(t, biz)
	assert.Same(t, userUC, biz.User)
	assert.Same(t, roleUC, biz.Role)
	assert.Same(t, menuUC, biz.Menu)
	assert.Same(t, btnUC, biz.Button)
	assert.Same(t, apiUC, biz.Api)
	assert.Same(t, authUC, biz.Auth)
	assert.Same(t, authUC, biz.User.auth)
}
