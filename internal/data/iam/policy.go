package iam

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"grain/pkg/auth"
)

// ReconcileIAMPolicies rebuilds the IAM-owned Casbin rules from the relational
// IAM tables. The database is the source of truth; the Casbin adapter is not.
func (d *Data) ReconcileIAMPolicies(ctx context.Context) error {
	if d == nil || d.gormdb == nil {
		return fmt.Errorf("iam policy reconciliation: database is required")
	}
	if d.enforcer == nil {
		return fmt.Errorf("iam policy reconciliation: enforcer is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	d.policyMu.Lock()
	defer d.policyMu.Unlock()

	var apis []apiPO
	var roles []rolePO
	var menus []menuPO
	var buttons []buttonPO
	if err := d.gormdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Order("id ASC").Find(&apis).Error; err != nil {
			return err
		}
		if err := tx.Preload("Apis").Preload("Menus").Preload("Buttons").Order("id ASC").Find(&roles).Error; err != nil {
			return err
		}
		if err := tx.Preload("Apis").Order("id ASC").Find(&menus).Error; err != nil {
			return err
		}
		if err := tx.Preload("Apis").Order("id ASC").Find(&buttons).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("iam policy reconciliation: load snapshot: %w", err)
	}

	desiredPolicies := make([][]string, 0, len(apis))
	desiredGroups := make([][]string, 0)
	policySeen := make(map[string]struct{})
	groupSeen := make(map[string]struct{})
	addPolicy := func(rule []string) {
		key := strings.Join(rule, "\x00")
		if _, ok := policySeen[key]; ok {
			return
		}
		policySeen[key] = struct{}{}
		desiredPolicies = append(desiredPolicies, rule)
	}
	addGroup := func(rule []string) {
		key := strings.Join(rule, "\x00")
		if _, ok := groupSeen[key]; ok {
			return
		}
		groupSeen[key] = struct{}{}
		desiredGroups = append(desiredGroups, rule)
	}

	for _, api := range apis {
		if api.ID == 0 || strings.TrimSpace(api.URL) == "" || strings.TrimSpace(api.Method) == "" {
			return fmt.Errorf("iam policy reconciliation: invalid API row %d", api.ID)
		}
		addPolicy([]string{auth.ApiToSubject(api.ID), api.URL, strings.ToUpper(api.Method)})
	}
	for _, role := range roles {
		if role.ID == 0 {
			return fmt.Errorf("iam policy reconciliation: invalid role row")
		}
		roleSub := auth.RoleToSubject(role.ID)
		for _, api := range role.Apis {
			if api.ID > 0 {
				addGroup([]string{roleSub, auth.ApiToSubject(api.ID)})
			}
		}
		for _, menu := range role.Menus {
			if menu.ID > 0 {
				addGroup([]string{roleSub, auth.MenuToSubject(menu.ID)})
			}
		}
		for _, button := range role.Buttons {
			if button.ID > 0 {
				addGroup([]string{roleSub, auth.ButtonToSubject(button.ID)})
			}
		}
	}
	for _, menu := range menus {
		if menu.ID == 0 {
			return fmt.Errorf("iam policy reconciliation: invalid menu row")
		}
		menuSub := auth.MenuToSubject(menu.ID)
		if menu.ParentID != nil && *menu.ParentID > 0 && *menu.ParentID != menu.ID {
			addGroup([]string{menuSub, auth.MenuToSubject(*menu.ParentID)})
		}
		for _, api := range menu.Apis {
			if api.ID > 0 {
				addGroup([]string{menuSub, auth.ApiToSubject(api.ID)})
			}
		}
	}
	for _, button := range buttons {
		if button.ID == 0 || button.MenuID == 0 {
			return fmt.Errorf("iam policy reconciliation: invalid button row %d", button.ID)
		}
		buttonSub := auth.ButtonToSubject(button.ID)
		addGroup([]string{buttonSub, auth.MenuToSubject(button.MenuID)})
		for _, api := range button.Apis {
			if api.ID > 0 {
				addGroup([]string{buttonSub, auth.ApiToSubject(api.ID)})
			}
		}
	}

	currentPolicies, err := d.enforcer.GetPolicy()
	if err != nil {
		return fmt.Errorf("iam policy reconciliation: read policies: %w", err)
	}
	currentGroups, err := d.enforcer.GetGroupingPolicy()
	if err != nil {
		return fmt.Errorf("iam policy reconciliation: read grouping policies: %w", err)
	}
	isIAM := func(value string) bool {
		subject, ok := auth.ParseSubject(value)
		return ok && subject.IsIAM()
	}
	// IAM owns rules whose subject (the first element) belongs to the IAM
	// authority. Rules where another authority's subject inherits an IAM object
	// are consumer-owned and must survive reconciliation.
	oldPolicies := filterRules(currentPolicies, func(rule []string) bool { return len(rule) > 0 && isIAM(rule[0]) })
	oldGroups := filterRules(currentGroups, func(rule []string) bool {
		return len(rule) > 1 && isIAM(rule[0])
	})

	restore := func() error {
		var restoreErrs []error
		if policies, readErr := d.enforcer.GetPolicy(); readErr != nil {
			restoreErrs = append(restoreErrs, readErr)
		} else {
			for _, rule := range filterRules(policies, func(rule []string) bool { return len(rule) > 0 && isIAM(rule[0]) }) {
				if _, removeErr := d.enforcer.RemovePolicy(rule); removeErr != nil {
					restoreErrs = append(restoreErrs, removeErr)
				}
			}
		}
		if groups, readErr := d.enforcer.GetGroupingPolicy(); readErr != nil {
			restoreErrs = append(restoreErrs, readErr)
		} else {
			for _, rule := range filterRules(groups, func(rule []string) bool {
				return len(rule) > 1 && isIAM(rule[0])
			}) {
				if _, removeErr := d.enforcer.RemoveGroupingPolicy(rule); removeErr != nil {
					restoreErrs = append(restoreErrs, removeErr)
				}
			}
		}
		if len(oldPolicies) > 0 {
			if _, addErr := d.enforcer.AddPoliciesEx(oldPolicies); addErr != nil {
				restoreErrs = append(restoreErrs, addErr)
			}
		}
		if len(oldGroups) > 0 {
			if _, addErr := d.enforcer.AddGroupingPoliciesEx(oldGroups); addErr != nil {
				restoreErrs = append(restoreErrs, addErr)
			}
		}
		return stderrors.Join(restoreErrs...)
	}

	for _, rule := range oldPolicies {
		if _, err := d.enforcer.RemovePolicy(rule); err != nil {
			restoreErr := restore()
			return fmt.Errorf("iam policy reconciliation: remove stale policy: %w", stderrors.Join(err, restoreErr))
		}
	}
	for _, rule := range oldGroups {
		if _, err := d.enforcer.RemoveGroupingPolicy(rule); err != nil {
			restoreErr := restore()
			return fmt.Errorf("iam policy reconciliation: remove stale grouping policy: %w", stderrors.Join(err, restoreErr))
		}
	}
	if len(desiredPolicies) > 0 {
		if _, err := d.enforcer.AddPoliciesEx(desiredPolicies); err != nil {
			restoreErr := restore()
			return fmt.Errorf("iam policy reconciliation: add policies: %w", stderrors.Join(err, restoreErr))
		}
	}
	if len(desiredGroups) > 0 {
		if _, err := d.enforcer.AddGroupingPoliciesEx(desiredGroups); err != nil {
			restoreErr := restore()
			return fmt.Errorf("iam policy reconciliation: add grouping policies: %w", stderrors.Join(err, restoreErr))
		}
	}
	return nil
}

func filterRules(rules [][]string, keep func([]string) bool) [][]string {
	filtered := make([][]string, 0, len(rules))
	for _, rule := range rules {
		if keep(rule) {
			filtered = append(filtered, append([]string(nil), rule...))
		}
	}
	return filtered
}
