package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthzAdminTokenGrantsAdmin(t *testing.T) {
	rbac, err := newAuthz("admintok", "")
	if err != nil {
		t.Fatal(err)
	}
	if !rbac.configured() {
		t.Fatal("an admin token should configure authz")
	}
	if got := rbac.role("admintok"); got != RoleAdmin {
		t.Errorf("admin token role = %v, want admin", got)
	}
	if got := rbac.role("nope"); got != RoleNone {
		t.Errorf("unknown token role = %v, want none", got)
	}
}

func TestAuthzUnconfiguredWhenNoTokens(t *testing.T) {
	rbac, err := newAuthz("", "")
	if err != nil {
		t.Fatal(err)
	}
	if rbac.configured() {
		t.Error("no tokens should leave authz unconfigured (endpoints refused)")
	}
}

func TestAuthzRBACFileGrants(t *testing.T) {
	body := "tokens:\n  - {token: v, role: viewer}\n  - {token: o, role: operator}\n"
	path := filepath.Join(t.TempDir(), "rbac.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rbac, err := newAuthz("boss", path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for token, want := range map[string]Role{"boss": RoleAdmin, "v": RoleViewer, "o": RoleOperator} {
		if got := rbac.role(token); got != want {
			t.Errorf("role(%q) = %v, want %v", token, got, want)
		}
	}
}

func TestAuthzRBACFileRejectsUnknownRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rbac.yaml")
	if err := os.WriteFile(path, []byte("tokens:\n  - {token: x, role: superuser}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAuthz("", path); err == nil {
		t.Fatal("expected an error for an unknown role")
	}
}

func TestRoleContextRoundTrip(t *testing.T) {
	if got := roleFromContext(withRole(context.Background(), RoleOperator)); got != RoleOperator {
		t.Errorf("role from context = %v, want operator", got)
	}
	if got := roleFromContext(context.Background()); got != RoleNone {
		t.Errorf("empty context role = %v, want none", got)
	}
}
