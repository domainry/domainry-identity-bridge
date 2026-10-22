package moduleassembly

import (
	"path/filepath"
	"testing"

	"github.com/domainry/domainry-foundation/entityid"
	"github.com/domainry/domainry-foundation/requestcontext"
	identity "github.com/domainry/domainry-identity-sdk"
)

func TestExternalDirectoryUsesExplicitBusinessIdentities(t *testing.T) {
	host := openHost(t, filepath.Join(t.TempDir(), "identities.db"))
	binding := testBinding(t, host, "app-one")
	publish(t, binding)
	principal, err := binding.Authenticate(t.Context(), "external-subject")
	if err != nil {
		t.Fatal(err)
	}
	if principal.User.UserID != principal.UserID || entityid.Validate("user", principal.User.UserID) != nil {
		t.Fatal("external user projection lost its business identity")
	}
	ctx := requestcontext.WithWorkspaceID(t.Context(), principal.WorkspaceID)
	user, found, err := binding.Projection().FindUser(ctx, identity.UserLookup{UserID: identity.SubjectID(principal.UserID)})
	if err != nil || !found || user.UserID != principal.UserID {
		t.Fatalf("business user lookup: found=%v err=%v", found, err)
	}
	roles, err := binding.Projection().ListRoles(ctx, identity.ProjectionQuery{})
	if err != nil || len(roles) != 1 || entityid.Validate("role", roles[0].RoleID) != nil || roles[0].RoleID == roles[0].Key || roles[0].RoleID != principal.Roles[0].RoleID {
		t.Fatalf("role projection: roles=%+v err=%v", roles, err)
	}
	assignments, err := binding.Projection().ListUserRoleAssignments(ctx, identity.UserRoleAssignmentQuery{UserID: identity.SubjectID(principal.UserID)})
	if err != nil || len(assignments) != 1 || assignments[0].UserID != user.UserID || assignments[0].RoleID != roles[0].RoleID {
		t.Fatalf("assignment business references: assignments=%+v err=%v", assignments, err)
	}
	otherApplication := testBinding(t, host, "app-two")
	publish(t, otherApplication)
	other, err := otherApplication.Authenticate(t.Context(), "external-subject")
	if err != nil || other.UserID != principal.UserID || other.Roles[0].RoleID == roles[0].RoleID {
		t.Fatal("application role identity must be isolated without allocating a second personal user")
	}
	again, err := binding.Authenticate(t.Context(), "external-subject")
	if err != nil || again.Roles[0].RoleID != roles[0].RoleID {
		t.Fatal("reconciliation changed a source-owned role identity")
	}
}
