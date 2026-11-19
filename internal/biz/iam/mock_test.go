package iam

import (
	"context"
	"errors"
	"time"

	"grain/pkg/db"
)

// mockApiRepo is an in-memory mock for ApiRepo
type mockApiRepo struct {
	apis                map[uint64]*Api
	nextID              uint64
	createErr           error
	updateErr           error
	deleteErr           error
	findByIDErr         error
	findByURLErr        error
	findByRoutesErr     error
	listErr             error
	syncErr             error
	addPolicyErr        error
	addPoliciesErr      error
	updatePolicyErr     error
	removePolicyErr     error
	addPolicyCalled     bool
	addPoliciesCalled   bool
	updatePolicyCalled  bool
	removePolicyCalled  bool
	lastPolicyApi       *Api
	lastPoliciesApis    []Api
	lastPolicyOldApi    *Api
	lastPolicyNewApi    *Api
	lastRemoveInherited bool
}

func newMockApiRepo() *mockApiRepo {
	return &mockApiRepo{
		apis:   make(map[uint64]*Api),
		nextID: 1,
	}
}

func (m *mockApiRepo) Create(ctx context.Context, api *Api) (*Api, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	cp := *api
	cp.ID = m.nextID
	m.nextID++
	m.apis[cp.ID] = &cp
	return &cp, nil
}

func (m *mockApiRepo) Update(ctx context.Context, api *Api) (*Api, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	cp := *api
	m.apis[cp.ID] = &cp
	return &cp, nil
}

func (m *mockApiRepo) Delete(ctx context.Context, id uint64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.apis, id)
	return nil
}

func (m *mockApiRepo) FindByID(ctx context.Context, id uint64) (*Api, error) {
	if m.findByIDErr != nil {
		return nil, m.findByIDErr
	}
	a, ok := m.apis[id]
	if !ok {
		return nil, nil
	}
	cp := *a
	return &cp, nil
}

func (m *mockApiRepo) FindByIDs(ctx context.Context, ids []uint64) ([]Api, error) {
	var res []Api
	for _, id := range ids {
		if a, ok := m.apis[id]; ok {
			res = append(res, *a)
		}
	}
	return res, nil
}

func (m *mockApiRepo) FindByURLAndMethod(ctx context.Context, url, method string) (*Api, error) {
	if m.findByURLErr != nil {
		return nil, m.findByURLErr
	}
	for _, a := range m.apis {
		if a.URL == url && a.Method == method {
			return a, nil
		}
	}
	return nil, nil
}

func (m *mockApiRepo) List(ctx context.Context, opts db.ListOptions) ([]Api, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	var res []Api
	for _, a := range m.apis {
		res = append(res, *a)
	}
	return res, int64(len(res)), nil
}

func (m *mockApiRepo) SyncRoutes(ctx context.Context, routes []ApiRoute) (int, error) {
	if m.syncErr != nil {
		return 0, m.syncErr
	}
	count := 0
	for _, r := range routes {
		found := false
		for _, a := range m.apis {
			if a.URL == r.URL && a.Method == r.Method {
				found = true
				break
			}
		}
		if !found {
			_, _ = m.Create(ctx, &Api{
				URL:    r.URL,
				Method: r.Method,
				Label:  r.Label,
				Descr:  r.Descr,
			})
			count++
		}
	}
	return count, nil
}

func (m *mockApiRepo) FindByRoutes(ctx context.Context, routes []ApiRoute) ([]Api, error) {
	if m.findByRoutesErr != nil {
		return nil, m.findByRoutesErr
	}
	var res []Api
	for _, rt := range routes {
		for _, a := range m.apis {
			if a.URL == rt.URL && a.Method == rt.Method {
				res = append(res, *a)
				break
			}
		}
	}
	return res, nil
}

func (m *mockApiRepo) AddPolicy(ctx context.Context, api *Api) error {
	m.addPolicyCalled = true
	m.lastPolicyApi = api
	return m.addPolicyErr
}

func (m *mockApiRepo) AddPolicies(ctx context.Context, apis []Api) error {
	m.addPoliciesCalled = true
	m.lastPoliciesApis = apis
	return m.addPoliciesErr
}

func (m *mockApiRepo) UpdatePolicy(ctx context.Context, oldApi, newApi *Api) error {
	m.updatePolicyCalled = true
	m.lastPolicyOldApi = oldApi
	m.lastPolicyNewApi = newApi
	return m.updatePolicyErr
}

func (m *mockApiRepo) RemovePolicy(ctx context.Context, api *Api, removeInherited bool) error {
	m.removePolicyCalled = true
	m.lastPolicyApi = api
	m.lastRemoveInherited = removeInherited
	return m.removePolicyErr
}

// mockButtonRepo is an in-memory mock for ButtonRepo
type mockButtonRepo struct {
	buttons                 map[uint64]*Button
	nextID                  uint64
	createErr               error
	updateErr               error
	deleteErr               error
	findByIDErr             error
	findByNameErr           error
	listErr                 error
	addGroupPolicyErr       error
	removeGroupPolicyErr    error
	addGroupPolicyCalled    bool
	removeGroupPolicyCalled bool
	lastGroupPolicyButton   *Button
}

func newMockButtonRepo() *mockButtonRepo {
	return &mockButtonRepo{
		buttons: make(map[uint64]*Button),
		nextID:  1,
	}
}

func (m *mockButtonRepo) Create(ctx context.Context, button *Button) (*Button, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	cp := *button
	cp.ID = m.nextID
	m.nextID++
	m.buttons[cp.ID] = &cp
	return &cp, nil
}

func (m *mockButtonRepo) Update(ctx context.Context, button *Button) (*Button, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	cp := *button
	m.buttons[cp.ID] = &cp
	return &cp, nil
}

func (m *mockButtonRepo) Delete(ctx context.Context, id uint64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.buttons, id)
	return nil
}

func (m *mockButtonRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*Button, error) {
	if m.findByIDErr != nil {
		return nil, m.findByIDErr
	}
	b, ok := m.buttons[id]
	if !ok {
		return nil, nil
	}
	cp := *b
	return &cp, nil
}

func (m *mockButtonRepo) FindByIDs(ctx context.Context, ids []uint64, preloads ...string) ([]Button, error) {
	var res []Button
	for _, id := range ids {
		if b, ok := m.buttons[id]; ok {
			res = append(res, *b)
		}
	}
	return res, nil
}

func (m *mockButtonRepo) FindByName(ctx context.Context, name string) (*Button, error) {
	if m.findByNameErr != nil {
		return nil, m.findByNameErr
	}
	for _, b := range m.buttons {
		if b.Name == name {
			return b, nil
		}
	}
	return nil, nil
}

func (m *mockButtonRepo) List(ctx context.Context, opts db.ListOptions) ([]Button, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	var res []Button
	for _, b := range m.buttons {
		// Filter by menu_id if specified in filters
		match := true
		for _, f := range opts.Filters {
			if f.Field == "menu_id" {
				if val, ok := f.Value.(uint64); ok && b.MenuID != val {
					match = false
					break
				}
			}
		}
		if match {
			res = append(res, *b)
		}
	}
	return res, int64(len(res)), nil
}

func (m *mockButtonRepo) ListAllWithApis(ctx context.Context) ([]Button, error) {
	var res []Button
	for _, b := range m.buttons {
		res = append(res, *b)
	}
	return res, nil
}

func (m *mockButtonRepo) AddGroupPolicy(ctx context.Context, button *Button) error {
	m.addGroupPolicyCalled = true
	m.lastGroupPolicyButton = button
	return m.addGroupPolicyErr
}

func (m *mockButtonRepo) RemoveGroupPolicy(ctx context.Context, button *Button, removeInherited bool) error {
	m.removeGroupPolicyCalled = true
	return m.removeGroupPolicyErr
}

// mockMenuRepo is an in-memory mock for MenuRepo
type mockMenuRepo struct {
	menus                   map[uint64]*Menu
	nextID                  uint64
	createErr               error
	updateErr               error
	deleteErr               error
	findByIDErr             error
	findByNameErr           error
	findByPathErr           error
	listErr                 error
	listAllErr              error
	countChildrenErr        error
	addGroupPolicyErr       error
	removeGroupPolicyErr    error
	addGroupPolicyCalled    bool
	removeGroupPolicyCalled bool
	lastGroupPolicyMenu     *Menu
}

func newMockMenuRepo() *mockMenuRepo {
	return &mockMenuRepo{
		menus:  make(map[uint64]*Menu),
		nextID: 1,
	}
}

func (m *mockMenuRepo) Create(ctx context.Context, menu *Menu) (*Menu, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	cp := *menu
	cp.ID = m.nextID
	m.nextID++
	m.menus[cp.ID] = &cp
	return &cp, nil
}

func (m *mockMenuRepo) Update(ctx context.Context, menu *Menu) (*Menu, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	cp := *menu
	m.menus[cp.ID] = &cp
	return &cp, nil
}

func (m *mockMenuRepo) Delete(ctx context.Context, id uint64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.menus, id)
	return nil
}

func (m *mockMenuRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*Menu, error) {
	if m.findByIDErr != nil {
		return nil, m.findByIDErr
	}
	menu, ok := m.menus[id]
	if !ok {
		return nil, nil
	}
	cp := *menu
	return &cp, nil
}

func (m *mockMenuRepo) FindByIDs(ctx context.Context, ids []uint64, preloads ...string) ([]Menu, error) {
	var res []Menu
	for _, id := range ids {
		if menu, ok := m.menus[id]; ok {
			res = append(res, *menu)
		}
	}
	return res, nil
}

func (m *mockMenuRepo) FindByName(ctx context.Context, name string) (*Menu, error) {
	if m.findByNameErr != nil {
		return nil, m.findByNameErr
	}
	for _, menu := range m.menus {
		if menu.Name == name {
			cp := *menu
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *mockMenuRepo) FindByPath(ctx context.Context, path string) (*Menu, error) {
	if m.findByPathErr != nil {
		return nil, m.findByPathErr
	}
	for _, menu := range m.menus {
		if menu.Path == path {
			cp := *menu
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *mockMenuRepo) List(ctx context.Context, opts db.ListOptions) ([]Menu, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	var res []Menu
	for _, menu := range m.menus {
		res = append(res, *menu)
	}
	return res, int64(len(res)), nil
}

func (m *mockMenuRepo) ListAllWithApis(ctx context.Context) ([]Menu, error) {
	if m.listAllErr != nil {
		return nil, m.listAllErr
	}
	var res []Menu
	for _, menu := range m.menus {
		res = append(res, *menu)
	}
	return res, nil
}

func (m *mockMenuRepo) CountChildren(ctx context.Context, parentID uint64) (int64, error) {
	if m.countChildrenErr != nil {
		return 0, m.countChildrenErr
	}
	var count int64
	for _, menu := range m.menus {
		if menu.ParentID != nil && *menu.ParentID == parentID {
			count++
		}
	}
	return count, nil
}

func (m *mockMenuRepo) AddGroupPolicy(ctx context.Context, menu *Menu) error {
	m.addGroupPolicyCalled = true
	m.lastGroupPolicyMenu = menu
	return m.addGroupPolicyErr
}

func (m *mockMenuRepo) RemoveGroupPolicy(ctx context.Context, menu *Menu, removeInherited bool) error {
	m.removeGroupPolicyCalled = true
	return m.removeGroupPolicyErr
}

// mockRoleRepo is an in-memory mock for RoleRepo
type mockRoleRepo struct {
	roles                   map[uint64]*Role
	nextID                  uint64
	userCounts              map[uint64]int64
	createErr               error
	updateErr               error
	deleteErr               error
	findByIDErr             error
	findByNameErr           error
	listErr                 error
	listAllErr              error
	countUsersErr           error
	addGroupPolicyErr       error
	removeGroupPolicyErr    error
	addGroupPolicyCalled    bool
	removeGroupPolicyCalled bool
	lastGroupPolicyRole     *Role
}

func newMockRoleRepo() *mockRoleRepo {
	return &mockRoleRepo{
		roles:      make(map[uint64]*Role),
		userCounts: make(map[uint64]int64),
		nextID:     1,
	}
}

func (m *mockRoleRepo) Create(ctx context.Context, role *Role) (*Role, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	cp := *role
	cp.ID = m.nextID
	m.nextID++
	m.roles[cp.ID] = &cp
	return &cp, nil
}

func (m *mockRoleRepo) Update(ctx context.Context, role *Role) (*Role, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	cp := *role
	m.roles[cp.ID] = &cp
	return &cp, nil
}

func (m *mockRoleRepo) Delete(ctx context.Context, id uint64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.roles, id)
	return nil
}

func (m *mockRoleRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*Role, error) {
	if m.findByIDErr != nil {
		return nil, m.findByIDErr
	}
	r, ok := m.roles[id]
	if !ok {
		return nil, nil
	}
	cp := *r
	return &cp, nil
}

func (m *mockRoleRepo) FindByName(ctx context.Context, name string) (*Role, error) {
	if m.findByNameErr != nil {
		return nil, m.findByNameErr
	}
	for _, r := range m.roles {
		if r.Name == name {
			cp := *r
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *mockRoleRepo) List(ctx context.Context, opts db.ListOptions) ([]Role, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	var res []Role
	for _, r := range m.roles {
		res = append(res, *r)
	}
	return res, int64(len(res)), nil
}

func (m *mockRoleRepo) ListAllWithRelations(ctx context.Context) ([]Role, error) {
	if m.listAllErr != nil {
		return nil, m.listAllErr
	}
	var res []Role
	for _, r := range m.roles {
		res = append(res, *r)
	}
	return res, nil
}

func (m *mockRoleRepo) CountUsersByRoleID(ctx context.Context, roleID uint64) (int64, error) {
	if m.countUsersErr != nil {
		return 0, m.countUsersErr
	}
	return m.userCounts[roleID], nil
}

func (m *mockRoleRepo) AddGroupPolicy(ctx context.Context, role *Role) error {
	m.addGroupPolicyCalled = true
	m.lastGroupPolicyRole = role
	return m.addGroupPolicyErr
}

func (m *mockRoleRepo) RemoveGroupPolicy(ctx context.Context, role *Role) error {
	m.removeGroupPolicyCalled = true
	return m.removeGroupPolicyErr
}

// mockUserRepo is an in-memory mock for UserRepo
type mockUserRepo struct {
	users                      map[uint64]*User
	deletedUsernames           map[string]struct{}
	tokenVersions              map[uint64]uint64
	consumedTokens             map[string]bool
	nextID                     uint64
	createErr                  error
	updateErr                  error
	deleteErr                  error
	findByIDErr                error
	findByUsernameErr          error
	listErr                    error
	listIDsByRoleErr           error
	incrementTokenVersionErr   error
	incrementBatchErr          error
	getTokenVersionErr         error
	ensureTokenVersionCacheErr error
	consumeRefreshErr          error
	rotateFamilyErr            error
	rotateResult               RotateFamilyResult
	loginFailures              map[string]int64
	loginFailureErr            error
	incrementVersionCalled     map[uint64]int
	incrementBatchCalled       []uint64
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users:                  make(map[uint64]*User),
		deletedUsernames:       make(map[string]struct{}),
		tokenVersions:          make(map[uint64]uint64),
		consumedTokens:         make(map[string]bool),
		nextID:                 1,
		incrementVersionCalled: make(map[uint64]int),
		rotateResult:           RotateFamilySuccess,
		loginFailures:          make(map[string]int64),
	}
}

func (m *mockUserRepo) GetLoginFailure(ctx context.Context, username string) (int64, error) {
	if m.loginFailureErr != nil {
		return 0, m.loginFailureErr
	}
	return m.loginFailures[username], nil
}

func (m *mockUserRepo) IncrementLoginFailure(ctx context.Context, username string, _ time.Duration) (int64, error) {
	if m.loginFailureErr != nil {
		return 0, m.loginFailureErr
	}
	m.loginFailures[username]++
	return m.loginFailures[username], nil
}

func (m *mockUserRepo) ClearLoginFailures(ctx context.Context, username string) error {
	if m.loginFailureErr != nil {
		return m.loginFailureErr
	}
	delete(m.loginFailures, username)
	return nil
}

func (m *mockUserRepo) Create(ctx context.Context, user *User) (*User, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	saved := *user
	saved.ID = m.nextID
	m.nextID++
	m.users[saved.ID] = &saved
	m.tokenVersions[saved.ID] = saved.TokenVersion
	ret := saved
	return &ret, nil
}

func (m *mockUserRepo) Update(ctx context.Context, user *User) (*User, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	existing, ok := m.users[user.ID]
	if !ok {
		return nil, errors.New("record not found")
	}
	if user.Username != "" {
		existing.Username = user.Username
	}
	if user.Password != "" {
		existing.Password = user.Password
	}
	if user.RoleID > 0 {
		existing.RoleID = user.RoleID
	}
	existing.IsActive = user.IsActive
	ret := *existing
	return &ret, nil
}

func (m *mockUserRepo) Delete(ctx context.Context, id uint64) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if u, ok := m.users[id]; ok {
		m.deletedUsernames[u.Username] = struct{}{}
	}
	delete(m.users, id)
	return nil
}

func (m *mockUserRepo) UsernameExists(ctx context.Context, username string) (bool, error) {
	if m.findByUsernameErr != nil {
		return false, m.findByUsernameErr
	}
	if _, ok := m.deletedUsernames[username]; ok {
		return true, nil
	}
	for _, u := range m.users {
		if u.Username == username {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockUserRepo) FindByID(ctx context.Context, id uint64, preloads ...string) (*User, error) {
	if m.findByIDErr != nil {
		return nil, m.findByIDErr
	}
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

func (m *mockUserRepo) FindByUsername(ctx context.Context, username string, preloads ...string) (*User, error) {
	if m.findByUsernameErr != nil {
		return nil, m.findByUsernameErr
	}
	for _, u := range m.users {
		if u.Username == username {
			cp := *u
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *mockUserRepo) List(ctx context.Context, opts db.ListOptions) ([]User, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	var res []User
	for _, u := range m.users {
		res = append(res, *u)
	}
	return res, int64(len(res)), nil
}

func (m *mockUserRepo) ListIDsByRole(ctx context.Context, roleID uint64) ([]uint64, error) {
	if m.listIDsByRoleErr != nil {
		return nil, m.listIDsByRoleErr
	}
	var ids []uint64
	for _, u := range m.users {
		if u.RoleID == roleID {
			ids = append(ids, u.ID)
		}
	}
	return ids, nil
}

func (m *mockUserRepo) IncrementTokenVersion(ctx context.Context, userID uint64) error {
	if m.incrementTokenVersionErr != nil {
		return m.incrementTokenVersionErr
	}
	m.tokenVersions[userID]++
	if u, ok := m.users[userID]; ok {
		u.TokenVersion = m.tokenVersions[userID]
	}
	m.incrementVersionCalled[userID]++
	return nil
}

func (m *mockUserRepo) IncrementTokenVersionBatch(ctx context.Context, userIDs []uint64) error {
	if m.incrementBatchErr != nil {
		return m.incrementBatchErr
	}
	for _, id := range userIDs {
		m.tokenVersions[id]++
		if u, ok := m.users[id]; ok {
			u.TokenVersion = m.tokenVersions[id]
		}
	}
	m.incrementBatchCalled = append(m.incrementBatchCalled, userIDs...)
	return nil
}

func (m *mockUserRepo) GetTokenVersion(ctx context.Context, userID uint64) (uint64, error) {
	if m.getTokenVersionErr != nil {
		return 0, m.getTokenVersionErr
	}
	return m.tokenVersions[userID], nil
}

func (m *mockUserRepo) EnsureTokenVersionCache(ctx context.Context, userID uint64, version uint64) error {
	if m.ensureTokenVersionCacheErr != nil {
		return m.ensureTokenVersionCacheErr
	}
	m.tokenVersions[userID] = version
	return nil
}

func (m *mockUserRepo) ConsumeRefreshToken(ctx context.Context, jti string, ttl time.Duration) (bool, error) {
	if m.consumeRefreshErr != nil {
		return false, m.consumeRefreshErr
	}
	if m.consumedTokens[jti] {
		return false, nil
	}
	m.consumedTokens[jti] = true
	return true, nil
}

func (m *mockUserRepo) RotateRefreshTokenFamily(ctx context.Context, familyID, oldJTI, newJTI string, userID uint64, ttl time.Duration) (RotateFamilyResult, error) {
	if m.rotateFamilyErr != nil {
		return RotateFamilyFailed, m.rotateFamilyErr
	}
	return m.rotateResult, nil
}
