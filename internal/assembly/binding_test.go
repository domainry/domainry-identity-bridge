package assembly

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/domainry/domainry-foundation/requestcontext"
	"github.com/domainry/domainry-identity-bridge/config"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/authorization/evaluator"
	"github.com/domainry/domainry-identity-sdk/modulehost"
	_ "modernc.org/sqlite"
)

// This fixture implements only host ownership, using actual SQL transactions.
// It deliberately has a single connection to detect nested pool acquisition.
type databaseHost struct {
	db         *sql.DB
	failCreate bool
}

func (*databaseHost) Driver() string { return "sqlite" }
func (*databaseHost) Schema() string { return "" }
func (h *databaseHost) ApplyOwnedMigrations(ctx context.Context, owner string, ms []modulehost.SchemaMigration) error {
	_, err := h.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _schema_migrations (owner TEXT,version INTEGER,PRIMARY KEY(owner,version))`)
	if err != nil {
		return err
	}
	return h.RunExternalWorkspaceTransaction(ctx, func(ctx context.Context, tx identity.EmbeddedTransaction) error {
		for _, m := range ms {
			var count int
			if err := tx.Executor.QueryRowContext(ctx, `SELECT COUNT(*) FROM _schema_migrations WHERE owner=? AND version=?`, owner, m.Version).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				continue
			}
			for _, s := range m.Statements {
				if _, err := tx.Executor.ExecContext(ctx, s); err != nil {
					return err
				}
			}
			if _, err := tx.Executor.ExecContext(ctx, `INSERT INTO _schema_migrations VALUES (?,?)`, owner, m.Version); err != nil {
				return err
			}
		}
		return nil
	})
}
func (h *databaseHost) RunExternalWorkspaceTransaction(ctx context.Context, f func(context.Context, identity.EmbeddedTransaction) error) error {
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := f(ctx, identity.EmbeddedTransaction{Executor: tx}); err != nil {
		return err
	}
	return tx.Commit()
}
func (h *databaseHost) CreateExternalWorkspace(ctx context.Context, r identity.ExternalWorkspaceCreate, tx identity.EmbeddedTransaction) error {
	_, err := tx.Executor.ExecContext(ctx, `INSERT INTO host_workspaces VALUES (?,?,1)`, r.WorkspaceID, r.UserID)
	if err != nil {
		return err
	}
	if h.failCreate {
		return errors.New("injected bootstrap failure")
	}
	return nil
}
func (h *databaseHost) InitializeExternalWorkspaceApplication(context.Context, identity.ExternalWorkspaceCreate, identity.EmbeddedTransaction) error {
	return nil
}
func (h *databaseHost) ExternalWorkspaceActive(ctx context.Context, id string) (bool, error) {
	var active bool
	err := h.db.QueryRowContext(ctx, `SELECT active FROM host_workspaces WHERE id=?`, id).Scan(&active)
	return active, err
}
func openHost(t *testing.T, path string) *databaseHost {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS host_workspaces (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,active INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	return &databaseHost{db: db}
}
func testBinding(t *testing.T, h *databaseHost, application string) *Binding {
	t.Helper()
	raw, err := os.ReadFile("../../examples/personal.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ApplicationKey = application
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subject == "external-credential-never-returned" {
			subject = "browser-user"
		}
		if subject == "invalid" {
			http.Error(w, "unauthorized", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"active": true, "token_type": "access", "audience": "example-application", "subject": map[string]any{"id": subject, "name": subject}, "expires_at": time.Now().Add(time.Hour).Unix()}})
	}))
	t.Cleanup(server.Close)
	cfg.Provider.Verification.Endpoint = server.URL
	cfg.Provider.Verification.ServiceHeaders = nil
	b, err := Open(t.Context(), cfg, identity.ApplicationRef{WorkspaceID: "installation", ApplicationKey: identity.ApplicationKey(application)}, identity.DatabaseHandle{Pool: h.db, Driver: "sqlite", ModuleMigrations: h, ExternalWorkspaces: h}, server.Client().Transport, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func publish(t *testing.T, b *Binding) {
	t.Helper()
	grants := []identity.ProjectRolePermission{}
	definitions := []identity.PermissionDefinition{}
	for _, op := range []string{"read", "create", "update", "export"} {
		grants = append(grants, identity.ProjectRolePermission{PermissionKey: "note." + op, DataScope: identity.DataScopeOwner})
		definitions = append(definitions, identity.PermissionDefinition{PermissionKey: "note." + op, ResourceKey: "note", OperationKey: op, Label: op, Category: "business", SourceKind: "manifest"})
	}
	request, err := identity.NewPermissionReconcileRequest(b.Application, "runtime", "", definitions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	_, err = b.PublishProjectRoles(t.Context(), identity.ProjectRoleCatalog{Application: b.Application, Objects: json.RawMessage(`[{"key":"note","fields":[{"key":"text"},{"key":"secret"}]}]`), Roles: []identity.ProjectRoleDefinition{{Key: "personal_owner", Name: "Owner", Audience: "user", AssignmentMode: "manual", ProvisionToWorkspaces: true, Permissions: grants, FieldPermissions: json.RawMessage(`[{"object_key":"note","field_key":"secret","read":false,"write":false,"export":false}]`), ExportRules: json.RawMessage(`[{"object_key":"note","mode":"selected_fields","fields":["text"]}]`)}}})
	if err != nil {
		t.Fatal(err)
	}
}
func TestPersonalWorkspacePersistsAndIsolatesAcrossApplications(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge.db")
	h := openHost(t, path)
	b := testBinding(t, h, "app-one")
	publish(t, b)
	first, err := b.Service.Authenticate(t.Context(), "9007199254740993")
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Service.Authenticate(t.Context(), "second")
	if err != nil {
		t.Fatal(err)
	}
	if first.WorkspaceID == second.WorkspaceID || first.UserID == second.UserID {
		t.Fatal("different accounts share authority")
	}
	for _, test := range []struct {
		subject string
		field   string
		allowed bool
	}{{first.UserID, "text", true}, {second.UserID, "text", false}, {first.UserID, "secret", false}} {
		d, err := evaluator.Evaluate(*first.AccessBundle, identity.AccessRequest{ObjectKey: "note", Action: "read", FieldKey: test.field}, identity.ResourceFacts{"owner_user_id": test.subject}, time.Now())
		if err != nil || d.Allowed != test.allowed {
			t.Fatalf("decision=%+v err=%v", d, err)
		}
	}
	if err := b.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.db.Ping(); err != nil {
		t.Fatal("binding closed host pool")
	}
	h.db.Close()
	h = openHost(t, path)
	b = testBinding(t, h, "app-one")
	again, err := b.Service.Authenticate(t.Context(), "9007199254740993")
	if err != nil {
		t.Fatal(err)
	}
	if again.WorkspaceID != first.WorkspaceID || again.UserID != first.UserID {
		t.Fatal("restart changed ownership")
	}
	otherApp := testBinding(t, h, "app-two")
	publish(t, otherApp)
	same, err := otherApp.Service.Authenticate(t.Context(), "9007199254740993")
	if err != nil {
		t.Fatal(err)
	}
	if same.WorkspaceID != first.WorkspaceID {
		t.Fatal("application change allocated second workspace")
	}
	ctx := identity.WithRequestIdentity(t.Context(), identity.RequestIdentity{Principal: first})
	if _, err := b.Projection().ListUsers(requestcontext.WithWorkspaceID(ctx, second.WorkspaceID), identity.ProjectionQuery{}); err == nil {
		t.Fatal("projection allowed cross-workspace access")
	}
}
func TestConcurrentFirstLoginAndBootstrapRollback(t *testing.T) {
	h := openHost(t, filepath.Join(t.TempDir(), "bridge.db"))
	b := testBinding(t, h, "app")
	publish(t, b)
	h.failCreate = true
	if _, err := b.Service.Authenticate(t.Context(), "rollback"); err == nil {
		t.Fatal("bootstrap failure accepted")
	}
	var count int
	h.db.QueryRow(`SELECT COUNT(*) FROM host_workspaces`).Scan(&count)
	if count != 0 {
		t.Fatal("orphan workspace")
	}
	h.db.QueryRow(`SELECT COUNT(*) FROM _external_identity_state WHERE kind='owner'`).Scan(&count)
	if count != 0 {
		t.Fatal("orphan owner")
	}
	h.failCreate = false
	const n = 20
	results := make(chan identity.Principal, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() { p, err := b.Service.Authenticate(t.Context(), "same"); results <- p; errs <- err })
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	workspace := ""
	for p := range results {
		if workspace != "" && workspace != p.WorkspaceID {
			t.Fatal("duplicate ownership")
		}
		workspace = p.WorkspaceID
	}
	h.db.QueryRow(`SELECT COUNT(*) FROM host_workspaces`).Scan(&count)
	if count != 1 {
		t.Fatalf("workspaces=%d", count)
	}
	if _, err := h.db.Exec(`UPDATE host_workspaces SET active=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Service.Authenticate(t.Context(), "same"); err == nil {
		t.Fatal("inactive workspace authenticated")
	}
}
func TestUnpublishedRoleCannotLeaveWorkspace(t *testing.T) {
	h := openHost(t, filepath.Join(t.TempDir(), "bridge.db"))
	b := testBinding(t, h, "app")
	if _, err := b.Service.Authenticate(t.Context(), "user"); err == nil {
		t.Fatal("unpublished role accepted")
	}
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM host_workspaces`).Scan(&n); err != nil || n != 0 {
		t.Fatal(fmt.Sprint(n, err))
	}
}

func TestPrincipalResolverRequiresExplicitWorkspaceAndConfiguredServiceRole(t *testing.T) {
	h := openHost(t, filepath.Join(t.TempDir(), "bridge.db"))
	b := testBinding(t, h, "app")
	publish(t, b)
	p, err := b.Authenticate(t.Context(), "person")
	if err != nil {
		t.Fatal(err)
	}
	if p.RoleKey != "personal_owner" || len(p.Roles) != 1 {
		t.Fatal("authenticated role projection missing")
	}
	if _, err := b.Resolve(t.Context(), identity.PrincipalResolutionRequest{SubjectID: identity.SubjectID(p.UserID)}); err == nil {
		t.Fatal("unscoped background principal accepted")
	}
	resolution, err := b.Resolve(requestcontext.WithWorkspaceID(t.Context(), p.WorkspaceID), identity.PrincipalResolutionRequest{SubjectID: identity.SubjectID(p.UserID)})
	if err != nil || resolution.Principal.UserID != p.UserID {
		t.Fatalf("background principal=%+v err=%v", resolution.Principal, err)
	}
	catalog, err := b.roles(t.Context(), b.Store.DB)
	if err != nil {
		t.Fatal(err)
	}
	b.Config.ServiceSubjects = []config.ServiceSubject{{ID: "workflow:nightly", RoleKeys: []string{"nightly"}}}
	catalog.Roles = append(catalog.Roles, identity.ProjectRoleDefinition{Key: "nightly", Name: "Nightly", Audience: "service", AssignmentMode: "system_managed", Permissions: []identity.ProjectRolePermission{{PermissionKey: "note.read", DataScope: identity.DataScopeAll}}})
	if _, err := b.PublishProjectRoles(t.Context(), catalog); err != nil {
		t.Fatal(err)
	}
	resolution, err = b.Resolve(requestcontext.WithWorkspaceID(t.Context(), p.WorkspaceID), identity.PrincipalResolutionRequest{SubjectID: "workflow:nightly", RoleKey: "nightly"})
	if err != nil || resolution.Principal.User.AccountType != "service" {
		t.Fatalf("service principal=%+v err=%v", resolution.Principal, err)
	}
	if _, err := b.Resolve(requestcontext.WithWorkspaceID(t.Context(), p.WorkspaceID), identity.PrincipalResolutionRequest{SubjectID: "workflow:invented", RoleKey: "nightly"}); err == nil {
		t.Fatal("invented service subject accepted")
	}
}
