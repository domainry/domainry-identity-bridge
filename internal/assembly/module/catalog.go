package moduleassembly

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/domainry/domainry-identity-bridge/internal/persistence"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-orm/sqlhost"
)

func (binding *Binding) saveCatalog(ctx context.Context, kind, owner string, value any) error {
	next, err := persistence.Encode(binding.namespace(), kind, binding.catalogKey(kind, owner), string(binding.Application.WorkspaceID), "", value)
	if err != nil {
		return err
	}
	return binding.Store.Host.RunExternalWorkspaceTransaction(ctx, func(ctx context.Context, tx identity.EmbeddedTransaction) error {
		previous, found, err := binding.Store.Get(ctx, tx.Executor, next.Key)
		if err != nil {
			return err
		}
		if !found {
			return binding.Store.Insert(ctx, tx.Executor, next)
		}
		if previous.Revision == next.Revision {
			return nil
		}
		return binding.Store.CompareAndSwap(ctx, tx.Executor, next, previous.Revision)
	})
}

func (binding *Binding) Register(ctx context.Context, request identity.ApplicationRegistration) (identity.ApplicationRegistrationReceipt, error) {
	if err := binding.checkApplication(request.Application); err != nil {
		return identity.ApplicationRegistrationReceipt{}, err
	}
	if err := request.ValidateContract(); err != nil {
		return identity.ApplicationRegistrationReceipt{}, err
	}
	if err := binding.saveCatalog(ctx, "application", "", request); err != nil {
		return identity.ApplicationRegistrationReceipt{}, err
	}
	return identity.ApplicationRegistrationReceipt{Application: request.Application, RedirectURLs: request.CanonicalRedirectURLs(), Status: "active", UpdatedAt: binding.Now().UTC().Format(time.RFC3339)}, nil
}

func (binding *Binding) CurrentSourceSnapshot(ctx context.Context, request identity.PermissionSourceSnapshotRequest) (identity.PermissionSourceSnapshot, error) {
	if err := request.ValidateContract(); err != nil {
		return identity.PermissionSourceSnapshot{}, err
	}
	result := identity.PermissionSourceSnapshot{SourceOwner: request.SourceOwner, Definitions: []identity.PermissionDefinition{}}
	record, found, err := binding.Store.Get(ctx, binding.Store.DB, binding.catalogKey("permissions", request.SourceOwner))
	if err != nil {
		return result, err
	}
	if found {
		err = json.Unmarshal(record.Payload, &result)
	}
	return result, err
}

func (binding *Binding) Reconcile(ctx context.Context, request identity.PermissionReconcileRequest) (identity.PermissionReconcileReceipt, error) {
	if err := request.ValidateContract(); err != nil {
		return identity.PermissionReconcileReceipt{}, err
	}
	result := identity.PermissionReconcileReceipt{SourceOwner: request.SourceOwner, SnapshotHash: request.SnapshotHash, PreviousSnapshotHash: request.PreviousSnapshotHash, DefinitionCount: len(request.Definitions)}
	err := binding.Store.Host.RunExternalWorkspaceTransaction(ctx, func(ctx context.Context, tx identity.EmbeddedTransaction) error {
		key := binding.catalogKey("permissions", request.SourceOwner)
		previous, found, err := binding.Store.Get(ctx, tx.Executor, key)
		if err != nil {
			return err
		}
		var snapshot identity.PermissionSourceSnapshot
		if found {
			if err := json.Unmarshal(previous.Payload, &snapshot); err != nil {
				return err
			}
		}
		if found && snapshot.SnapshotHash == request.SnapshotHash {
			result.PreviousSnapshotHash = request.SnapshotHash
			result.Unchanged = len(request.Definitions)
			return nil
		}
		if snapshot.SnapshotHash != request.PreviousSnapshotHash {
			return fmt.Errorf("external permission snapshot conflict")
		}
		next, err := persistence.Encode(binding.namespace(), "permissions", key, string(binding.Application.WorkspaceID), "", identity.PermissionSourceSnapshot{SourceOwner: request.SourceOwner, SnapshotHash: request.SnapshotHash, Definitions: request.Definitions})
		if err != nil {
			return err
		}
		oldDefinitions := map[string]identity.PermissionDefinition{}
		for _, definition := range snapshot.Definitions {
			oldDefinitions[definition.PermissionKey] = definition
		}
		for _, definition := range request.Definitions {
			if old, exists := oldDefinitions[definition.PermissionKey]; !exists {
				result.Inserted++
			} else if reflect.DeepEqual(old, definition) {
				result.Unchanged++
			} else {
				result.Updated++
			}
			delete(oldDefinitions, definition.PermissionKey)
		}
		result.Retired = len(oldDefinitions)
		if found {
			return binding.Store.CompareAndSwap(ctx, tx.Executor, next, previous.Revision)
		}
		return binding.Store.Insert(ctx, tx.Executor, next)
	})
	return result, err
}

func (binding *Binding) PublishProjectRoles(ctx context.Context, catalog identity.ProjectRoleCatalog) (identity.ProjectRoleCatalogReceipt, error) {
	catalog.SourceOwner = strings.TrimSpace(catalog.SourceOwner)
	if err := catalog.ValidateContract(); err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	if err := validateRoleCatalog(catalog); err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	var revision string
	err := binding.Store.Host.RunExternalWorkspaceTransaction(ctx, func(ctx context.Context, tx identity.EmbeddedTransaction) error {
		catalogs, err := binding.roleCatalogs(ctx, tx.Executor)
		if err != nil {
			return err
		}
		replaced := false
		for index := range catalogs {
			if catalogs[index].SourceOwner == catalog.SourceOwner {
				catalogs[index] = catalog
				replaced = true
				break
			}
		}
		if !replaced {
			catalogs = append(catalogs, catalog)
		}
		effective, err := mergeRoleCatalogs(catalogs)
		if err != nil {
			return err
		}
		if err := validateRoleSelection(effective, binding.Config.Workspace.InitialRoleKeys, false); err != nil {
			return err
		}
		for _, subject := range binding.Config.ServiceSubjects {
			if err := validateRoleSelection(effective, subject.RoleKeys, true); err != nil {
				return err
			}
		}
		key := binding.catalogKey("roles", catalog.SourceOwner)
		next, err := persistence.Encode(binding.namespace(), "roles", key, string(binding.Application.WorkspaceID), "", catalog)
		if err != nil {
			return err
		}
		revision = next.Revision
		previous, found, err := binding.Store.Get(ctx, tx.Executor, key)
		if err != nil {
			return err
		}
		if !found {
			return binding.Store.Insert(ctx, tx.Executor, next)
		}
		if previous.Revision == next.Revision {
			return nil
		}
		return binding.Store.CompareAndSwap(ctx, tx.Executor, next, previous.Revision)
	})
	if err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	return identity.ProjectRoleCatalogReceipt{SourceOwner: catalog.SourceOwner, Published: len(catalog.Roles), SHA256: revision}, nil
}

func (binding *Binding) roles(ctx context.Context, db sqlhost.DBTX) (identity.ProjectRoleCatalog, error) {
	catalogs, err := binding.roleCatalogs(ctx, db)
	if err != nil {
		return identity.ProjectRoleCatalog{}, err
	}
	if len(catalogs) == 0 {
		return identity.ProjectRoleCatalog{}, fmt.Errorf("external identity project roles have not been published")
	}
	return mergeRoleCatalogs(catalogs)
}

func (binding *Binding) roleCatalogs(ctx context.Context, db sqlhost.DBTX) ([]identity.ProjectRoleCatalog, error) {
	records, err := binding.Store.ListWith(ctx, db, binding.namespace(), "roles", string(binding.Application.WorkspaceID))
	if err != nil {
		return nil, err
	}
	catalogs := make([]identity.ProjectRoleCatalog, 0, len(records))
	for _, record := range records {
		var catalog identity.ProjectRoleCatalog
		if err := json.Unmarshal(record.Payload, &catalog); err != nil {
			return nil, err
		}
		catalog.SourceOwner = strings.TrimSpace(catalog.SourceOwner)
		if record.Key != binding.catalogKey("roles", catalog.SourceOwner) {
			continue
		}
		if err := catalog.ValidateContract(); err != nil {
			return nil, err
		}
		if err := validateRoleCatalog(catalog); err != nil {
			return nil, err
		}
		catalogs = append(catalogs, catalog)
	}
	sort.Slice(catalogs, func(left, right int) bool { return catalogs[left].SourceOwner < catalogs[right].SourceOwner })
	return catalogs, nil
}

func mergeRoleCatalogs(catalogs []identity.ProjectRoleCatalog) (identity.ProjectRoleCatalog, error) {
	effective := identity.ProjectRoleCatalog{}
	if len(catalogs) == 1 {
		effective.SourceOwner = catalogs[0].SourceOwner
	}
	owners := map[string]string{}
	for _, catalog := range catalogs {
		for _, role := range catalog.Roles {
			key := strings.TrimSpace(role.Key)
			if owner, found := owners[key]; found && owner != catalog.SourceOwner {
				return identity.ProjectRoleCatalog{}, fmt.Errorf("external project role %q is published by both %q and %q", key, owner, catalog.SourceOwner)
			}
			owners[key] = catalog.SourceOwner
			effective.Roles = append(effective.Roles, role)
		}
	}
	sort.Slice(effective.Roles, func(left, right int) bool { return effective.Roles[left].Key < effective.Roles[right].Key })
	objects, err := mergeRoleCatalogObjects(catalogs)
	if err != nil {
		return identity.ProjectRoleCatalog{}, err
	}
	effective.Objects = objects
	return effective, nil
}

func mergeRoleCatalogObjects(catalogs []identity.ProjectRoleCatalog) (json.RawMessage, error) {
	objects := map[string]json.RawMessage{}
	for _, catalog := range catalogs {
		if len(catalog.Objects) == 0 || string(catalog.Objects) == "null" {
			continue
		}
		var declared []json.RawMessage
		if err := json.Unmarshal(catalog.Objects, &declared); err != nil {
			return nil, fmt.Errorf("decode external project objects for %q: %w", catalog.SourceOwner, err)
		}
		for _, raw := range declared {
			var header struct {
				Key string `json:"key"`
			}
			var value any
			if err := json.Unmarshal(raw, &header); err != nil {
				return nil, err
			}
			key := strings.TrimSpace(header.Key)
			if key == "" {
				return nil, fmt.Errorf("external project object key is required")
			}
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, err
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			if previous, found := objects[key]; found && !bytes.Equal(previous, canonical) {
				return nil, fmt.Errorf("external project object %q has conflicting definitions", key)
			}
			objects[key] = canonical
		}
	}
	if len(objects) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	merged := make([]json.RawMessage, 0, len(keys))
	for _, key := range keys {
		merged = append(merged, objects[key])
	}
	return json.Marshal(merged)
}

func (binding *Binding) validateAssignedRoles(ctx context.Context, db sqlhost.DBTX, keys []string, service bool) error {
	catalog, err := binding.roles(ctx, db)
	if err != nil {
		return err
	}
	return validateRoleSelection(catalog, keys, service)
}

var _ identity.PermissionSnapshotReader = (*Binding)(nil)
