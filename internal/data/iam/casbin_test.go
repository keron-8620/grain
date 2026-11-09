package iam

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCasbin_Validation(t *testing.T) {
	ctx := context.Background()
	enf := setupTestEnforcer(t)

	t.Run("nil enforcer or nil ctx", func(t *testing.T) {
		err := AddPolicies(ctx, nil, [][]string{{"p", "/a", "GET"}})
		require.Error(t, err)

		err = AddPolicies(nil, enf, [][]string{{"p", "/a", "GET"}})
		require.Error(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		cancCtx, cancel := context.WithCancel(ctx)
		cancel()

		err := AddPolicies(cancCtx, enf, [][]string{{"p", "/a", "GET"}})
		require.Error(t, err)
	})

	t.Run("invalid rule length or empty elements", func(t *testing.T) {
		// Expected 3 elements, got 2
		err := AddPolicies(ctx, enf, [][]string{{"p", "GET"}})
		require.Error(t, err)

		// Empty element
		err = AddPolicies(ctx, enf, [][]string{{"p", "", "GET"}})
		require.Error(t, err)
	})

	t.Run("empty rules list short-circuits", func(t *testing.T) {
		err := AddPolicies(ctx, enf, nil)
		require.NoError(t, err)

		err = RemovePolicies(ctx, enf, nil)
		require.NoError(t, err)

		err = AddGroupPolicies(ctx, enf, nil)
		require.NoError(t, err)

		err = RemoveGroupPolicies(ctx, enf, nil)
		require.NoError(t, err)
	})

	t.Run("RemoveFilteredGroupingPolicy validation", func(t *testing.T) {
		_, err := RemoveFilteredGroupingPolicy(ctx, nil, 0, "role_1")
		require.Error(t, err)

		_, err = RemoveFilteredGroupingPolicy(ctx, enf, -1, "role_1")
		require.Error(t, err)

		_, err = RemoveFilteredGroupingPolicy(ctx, enf, 2, "role_1")
		require.Error(t, err)

		_, err = RemoveFilteredGroupingPolicy(ctx, enf, 0, "")
		require.Error(t, err)
	})
}
