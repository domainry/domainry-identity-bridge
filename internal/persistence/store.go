// Package persistence owns external identity projections and ownership bindings.
// Runtime-owned tables are accessed only through the injected host capability.
package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/modulehost"
	"github.com/domainry/domainry-orm/dialect"
	"github.com/domainry/domainry-orm/query"
	"github.com/domainry/domainry-orm/schema"
	"github.com/domainry/domainry-orm/sqlhost"
)

const stateTable = "_external_identity_state"

type Store struct {
	DB       *sql.DB
	Renderer dialect.Renderer
	Host     identity.ExternalWorkspaceHost
}

func Open(ctx context.Context, handle identity.DatabaseHandle) (*Store, error) {
	db, ok := handle.Pool.(*sql.DB)
	if !ok || db == nil || handle.ModuleMigrations == nil || handle.ExternalWorkspaces == nil {
		return nil, fmt.Errorf("external identity requires host database, migrations, and workspace capability")
	}
	renderer, err := dialect.ParseRenderer(handle.Driver, handle.Schema, "")
	if err != nil {
		return nil, err
	}
	ddl, args, err := schema.NewTable(renderer, stateTable).Columns(
		schema.Column("state_key", schema.TextKey(64)).NotNull(),
		schema.Column("namespace", schema.TextKey(64)).NotNull(),
		schema.Column("kind", schema.TextKey(32)).NotNull(),
		schema.Column("workspace_id", schema.TextKey(255)).NotNull(),
		schema.Column("subject_id", schema.TextKey(255)).NotNull(),
		schema.Column("revision", schema.TextKey(64)).NotNull(),
		schema.Column("payload", schema.Text()).NotNull(),
	).PrimaryKey("state_key").Build()
	if err != nil {
		return nil, err
	}
	if len(args) != 0 {
		return nil, fmt.Errorf("external identity schema must not contain bound DDL values")
	}
	if err := handle.ModuleMigrations.ApplyOwnedMigrations(ctx, "external_identity", []modulehost.SchemaMigration{{Version: 1, Name: "external_identity_state", Statements: []string{ddl}}}); err != nil {
		return nil, err
	}
	return &Store{DB: db, Renderer: renderer, Host: handle.ExternalWorkspaces}, nil
}

func Key(parts ...string) string {
	raw, _ := json.Marshal(parts)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

type Record struct {
	Key         string
	Namespace   string
	Kind        string
	WorkspaceID string
	SubjectID   string
	Revision    string
	Payload     json.RawMessage
}

func (store *Store) Get(ctx context.Context, db sqlhost.DBTX, key string) (Record, bool, error) {
	statement, args, err := query.NewSelectBuilder(store.Renderer, stateTable).Columns("state_key", "namespace", "kind", "workspace_id", "subject_id", "revision", "payload").Where(query.Equal("state_key", key)).Build()
	if err != nil {
		return Record{}, false, err
	}
	var value Record
	var payload string
	err = db.QueryRowContext(ctx, statement, args...).Scan(&value.Key, &value.Namespace, &value.Kind, &value.WorkspaceID, &value.SubjectID, &value.Revision, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	value.Payload = json.RawMessage(payload)
	return value, err == nil, err
}

func (store *Store) List(ctx context.Context, namespace, kind, workspaceID string) ([]Record, error) {
	predicates := []query.Predicate{query.Equal("namespace", namespace), query.Equal("kind", kind)}
	if workspaceID != "" {
		predicates = append(predicates, query.Equal("workspace_id", workspaceID))
	}
	statement, args, err := query.NewSelectBuilder(store.Renderer, stateTable).Columns("state_key", "namespace", "kind", "workspace_id", "subject_id", "revision", "payload").Where(query.And(predicates...)).Build()
	if err != nil {
		return nil, err
	}
	rows, err := store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []Record{}
	for rows.Next() {
		var value Record
		var payload string
		if err := rows.Scan(&value.Key, &value.Namespace, &value.Kind, &value.WorkspaceID, &value.SubjectID, &value.Revision, &payload); err != nil {
			return nil, err
		}
		value.Payload = json.RawMessage(payload)
		values = append(values, value)
	}
	return values, rows.Err()
}

func (store *Store) Insert(ctx context.Context, db sqlhost.DBTX, value Record) error {
	statement, args, err := query.NewInsertBuilder(store.Renderer, stateTable).Columns("state_key", "namespace", "kind", "workspace_id", "subject_id", "revision", "payload").Values(value.Key, value.Namespace, value.Kind, value.WorkspaceID, value.SubjectID, value.Revision, string(value.Payload)).Build()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, statement, args...)
	return err
}

// CompareAndSwap preserves immutable publication hashes and detects concurrent
// changes. Callers execute multi-record mutations inside the host transaction.
func (store *Store) CompareAndSwap(ctx context.Context, db sqlhost.DBTX, value Record, previous string) error {
	statement, args, err := query.NewUpdateBuilder(store.Renderer, stateTable).Set("revision", value.Revision).Set("payload", string(value.Payload)).Where(query.And(query.Equal("state_key", value.Key), query.Equal("revision", previous))).Build()
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, statement, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("external identity state revision conflict")
	}
	return nil
}

func Encode(namespace, kind, key, workspace, user string, value any) (Record, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Record{}, err
	}
	digest := sha256.Sum256(raw)
	return Record{Key: key, Namespace: namespace, Kind: kind, WorkspaceID: workspace, SubjectID: user, Revision: hex.EncodeToString(digest[:]), Payload: raw}, nil
}
