package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grain/pkg/auth"
	"grain/pkg/db"
)

func TestData_ReconcileIAMPolicies(t *testing.T) {
	ctx := context.Background()
	data, gormDB, enf, _ := setupTestData(t)

	api := apiPO{URL: "/api/v1/users", Method: "GET", Label: "list users"}
	require.NoError(t, gormDB.Create(&api).Error)
	menu := menuPO{Path: "/users", Component: "users", Name: "Users", IsActive: true}
	require.NoError(t, gormDB.Create(&menu).Error)
	button := buttonPO{Name: "create-user", MenuID: menu.ID, IsActive: true}
	require.NoError(t, gormDB.Create(&button).Error)
	role := rolePO{Name: "admin"}
	require.NoError(t, gormDB.Create(&role).Error)

	require.NoError(t, gormDB.Model(&menu).Association("Apis").Append(&api))
	require.NoError(t, gormDB.Model(&button).Association("Apis").Append(&api))
	require.NoError(t, gormDB.Model(&role).Association("Apis").Append(&api))
	require.NoError(t, gormDB.Model(&role).Association("Menus").Append(&menu))
	require.NoError(t, gormDB.Model(&role).Association("Buttons").Append(&button))

	// Foreign rules and stale IAM rules must not be mistaken for IAM state.
	_, err := enf.AddPolicy([]string{"llm:key:1", "/external", "GET"})
	require.NoError(t, err)
	_, err = enf.AddPolicy([]string{auth.ApiToSubject(9999), "/stale", "GET"})
	require.NoError(t, err)
	foreignGrant := []string{"llm:key:1", auth.ApiToSubject(api.ID)}
	_, err = enf.AddGroupingPolicy(foreignGrant)
	require.NoError(t, err)

	require.NoError(t, data.ReconcileIAMPolicies(ctx))

	allowed, err := enf.Enforce(auth.RoleToSubject(role.ID), "/api/v1/users", "GET")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = enf.Enforce(auth.RoleToSubject(role.ID), "/api/v1/users", "POST")
	require.NoError(t, err)
	assert.False(t, allowed)

	foreign, err := enf.HasPolicy([]string{"llm:key:1", "/external", "GET"})
	require.NoError(t, err)
	assert.True(t, foreign, "rules from other authorities must be preserved")

	stale, err := enf.HasPolicy([]string{auth.ApiToSubject(9999), "/stale", "GET"})
	require.NoError(t, err)
	assert.False(t, stale, "stale IAM rules must be removed")

	preservedGrant, err := enf.HasGroupingPolicy(foreignGrant)
	require.NoError(t, err)
	assert.True(t, preservedGrant, "consumer-owned grants to IAM objects must be preserved")

	// Reconciliation is idempotent.
	firstPolicies, err := enf.GetPolicy()
	require.NoError(t, err)
	firstGroups, err := enf.GetGroupingPolicy()
	require.NoError(t, err)
	require.NoError(t, data.ReconcileIAMPolicies(ctx))
	secondPolicies, err := enf.GetPolicy()
	require.NoError(t, err)
	secondGroups, err := enf.GetGroupingPolicy()
	require.NoError(t, err)
	assert.ElementsMatch(t, firstPolicies, secondPolicies)
	assert.ElementsMatch(t, firstGroups, secondGroups)
}

func TestData_ReconcileIAMPolicies_RestoresAfterRestart(t *testing.T) {
	ctx := context.Background()
	_, gormDB, _, _ := setupTestData(t)

	api := apiPO{URL: "/api/v1/roles", Method: "GET", Label: "list roles"}
	require.NoError(t, gormDB.Create(&api).Error)
	role := rolePO{Name: "viewer"}
	require.NoError(t, gormDB.Create(&role).Error)
	require.NoError(t, gormDB.Model(&role).Association("Apis").Append(&api))

	// A fresh process starts with a fresh enforcer and no durable adapter state.
	freshEnforcer := setupTestEnforcer(t)

	restarted := NewData(gormDB, NewMemoryUserCache(0), freshEnforcer, db.DBTimeout{}, db.DBSlowThreshold{}, auth.JWTConfig{})
	require.NoError(t, restarted.ReconcileIAMPolicies(ctx))

	allowed, err := freshEnforcer.Enforce(auth.RoleToSubject(role.ID), "/api/v1/roles", "GET")
	require.NoError(t, err)
	assert.True(t, allowed)
}
