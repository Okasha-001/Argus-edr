package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Role is an admin-API privilege level. Higher roles include the powers of lower
// ones, so a single >= comparison authorizes any endpoint.
type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleOperator
	RoleAdmin
)

var roleByName = map[string]Role{
	"viewer":   RoleViewer,
	"operator": RoleOperator,
	"admin":    RoleAdmin,
}

// String renders the role for audit entries and logs.
func (r Role) String() string {
	for name, role := range roleByName {
		if role == r {
			return name
		}
	}
	return "none"
}

// authz maps bearer tokens to roles. It is built from the single --admin-token
// (which grants admin, preserving the original behaviour) and/or an --rbac-file
// of token/role entries. With no tokens configured, state-changing endpoints stay
// refused — the secure default is unchanged.
type authz struct {
	grants []grant
}

type grant struct {
	token string
	role  Role
}

// newAuthz assembles the grant table. The admin token, when set, is always an
// admin grant; the RBAC file adds finer roles.
func newAuthz(adminToken, rbacFile string) (*authz, error) {
	rbac := &authz{}
	if adminToken != "" {
		rbac.grants = append(rbac.grants, grant{token: adminToken, role: RoleAdmin})
	}
	if rbacFile != "" {
		loaded, err := loadRBACFile(rbacFile)
		if err != nil {
			return nil, err
		}
		rbac.grants = append(rbac.grants, loaded...)
	}
	return rbac, nil
}

// configured reports whether any token grants access. When false, the guarded
// endpoints are refused outright rather than left open.
func (a *authz) configured() bool { return len(a.grants) > 0 }

// role returns the highest role granted to the presented token, or RoleNone. It
// compares every grant in constant time and never returns early, so neither a
// token's validity nor which grant it matched leaks through timing.
func (a *authz) role(presented string) Role {
	best := RoleNone
	for _, candidate := range a.grants {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(candidate.token)) == 1 && candidate.role > best {
			best = candidate.role
		}
	}
	return best
}

type contextKey int

const roleContextKey contextKey = iota

// withRole stashes the authorized role on the request context; roleFromContext
// reads it back in the handler so the audit log can name the actor.
func withRole(ctx context.Context, role Role) context.Context {
	return context.WithValue(ctx, roleContextKey, role)
}

func roleFromContext(ctx context.Context) Role {
	if role, ok := ctx.Value(roleContextKey).(Role); ok {
		return role
	}
	return RoleNone
}

type rbacFile struct {
	Tokens []struct {
		Token string `yaml:"token"`
		Role  string `yaml:"role"`
	} `yaml:"tokens"`
}

func loadRBACFile(path string) ([]grant, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rbac file: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var parsed rbacFile
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse rbac file %s: %w", path, err)
	}
	grants := make([]grant, 0, len(parsed.Tokens))
	for i, entry := range parsed.Tokens {
		role, ok := roleByName[entry.Role]
		if !ok {
			return nil, fmt.Errorf("rbac file %s: tokens[%d] has unknown role %q (want viewer|operator|admin)", path, i, entry.Role)
		}
		if entry.Token == "" {
			return nil, fmt.Errorf("rbac file %s: tokens[%d] has an empty token", path, i)
		}
		grants = append(grants, grant{token: entry.Token, role: role})
	}
	return grants, nil
}
