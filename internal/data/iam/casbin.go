package iam

import (
	"context"
	"fmt"
	"slices"

	emperror "emperror.dev/errors"
	"github.com/casbin/casbin/v3"
)

const (
	policyReloadAttempts = 3
)

func validatePolicyRules(ctx context.Context, enf *casbin.SyncedEnforcer, rules [][]string, expectedLen int) error {
	if enf == nil {
		return emperror.New("enforcer cannot be nil")
	}
	if ctx == nil {
		return emperror.New("context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return emperror.WrapIf(err, "context cancelled")
	}
	for _, rule := range rules {
		if len(rule) != expectedLen {
			return emperror.NewWithDetails(
				fmt.Sprintf("each rule must have exactly %d elements", expectedLen),
				"rule", rule,
			)
		}
		if slices.Contains(rule, "") {
			return emperror.NewWithDetails("rule element cannot be empty", "rule", rule)
		}
	}
	return nil
}

// AddPolicies adds batch authorization policies.
func AddPolicies(ctx context.Context, enf *casbin.SyncedEnforcer, rules [][]string) error {
	if err := validatePolicyRules(ctx, enf, rules, 3); err != nil {
		return emperror.WrapIf(err, "failed to add policies")
	}
	if len(rules) == 0 {
		return nil
	}
	if _, err := enf.AddPolicies(rules); err != nil {
		return emperror.WrapIfWithDetails(err, "failed to add policies", "count", len(rules))
	}
	return nil
}

// RemovePolicies removes batch authorization policies by exact rule match.
func RemovePolicies(ctx context.Context, enf *casbin.SyncedEnforcer, rules [][]string) error {
	if err := validatePolicyRules(ctx, enf, rules, 3); err != nil {
		return emperror.WrapIf(err, "failed to remove policies")
	}
	if len(rules) == 0 {
		return nil
	}
	if _, err := enf.RemovePolicies(rules); err != nil {
		return emperror.WrapIfWithDetails(err, "failed to remove policies", "count", len(rules))
	}
	return nil
}

// AddGroupPolicies adds batch grouping policies (e.g., role inheritance).
func AddGroupPolicies(ctx context.Context, enf *casbin.SyncedEnforcer, rules [][]string) error {
	if err := validatePolicyRules(ctx, enf, rules, 2); err != nil {
		return emperror.WrapIf(err, "failed to add grouping policies")
	}
	if len(rules) == 0 {
		return nil
	}
	if _, err := enf.AddGroupingPolicies(rules); err != nil {
		return emperror.WrapIfWithDetails(err, "failed to add grouping policies", "count", len(rules))
	}
	return nil
}

// RemoveGroupPolicies removes batch grouping policies by exact rule match.
func RemoveGroupPolicies(ctx context.Context, enf *casbin.SyncedEnforcer, rules [][]string) error {
	if err := validatePolicyRules(ctx, enf, rules, 2); err != nil {
		return emperror.WrapIf(err, "failed to remove grouping policies")
	}
	if len(rules) == 0 {
		return nil
	}
	if _, err := enf.RemoveGroupingPolicies(rules); err != nil {
		return emperror.WrapIfWithDetails(err, "failed to remove grouping policies", "count", len(rules))
	}
	return nil
}

// RemoveFilteredGroupingPolicy removes grouping policies matching the filter.
func RemoveFilteredGroupingPolicy(ctx context.Context, enf *casbin.SyncedEnforcer, index int, value string) (bool, error) {
	if enf == nil {
		return false, emperror.New("enforcer cannot be nil")
	}
	if ctx == nil {
		return false, emperror.New("context cannot be nil")
	}
	if err := ctx.Err(); err != nil {
		return false, emperror.WrapIf(err, "context cancelled")
	}
	if value == "" || index < 0 || index > 1 {
		return false, emperror.NewWithDetails("invalid filter: value non-empty and index must be 0 or 1", "index", index)
	}
	affected, err := enf.RemoveFilteredGroupingPolicy(index, value)
	if err != nil {
		return false, emperror.WrapIfWithDetails(err, "failed to remove filtered grouping policies", "index", index, "value", value)
	}
	return affected, nil
}
