package conf

// DefaultRBACModel is the standard RBAC model supporting role inheritance and RESTful path matching.
// - r: sub (user/role), obj (resource/path), act (action/method)
// - p: sub, obj, act
// - g: role inheritance
// - m: role match && path match (with keyMatch2 supporting /path/:id and /path/*) && act match
const DefaultRBACModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && (r.obj == p.obj || keyMatch2(r.obj, p.obj)) && (r.act == p.act || p.act == "*")
`
