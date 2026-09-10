package assembly

import (
	"context"
	"encoding/json"
	"fmt"
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
	if err := binding.checkApplication(request.Application); err != nil {
		return identity.PermissionSourceSnapshot{}, err
	}
	if err := request.ValidateContract(); err != nil {
		return identity.PermissionSourceSnapshot{}, err
	}
	result := identity.PermissionSourceSnapshot{WorkspaceID: request.Application.WorkspaceID, SourceOwner: request.SourceOwner, Definitions: []identity.PermissionDefinition{}}
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
	if err := binding.checkApplication(request.Application); err != nil {
		return identity.PermissionReconcileReceipt{}, err
	}
	if err := request.ValidateContract(); err != nil {
		return identity.PermissionReconcileReceipt{}, err
	}
	result := identity.PermissionReconcileReceipt{WorkspaceID: request.Application.WorkspaceID, SourceOwner: request.SourceOwner, SnapshotHash: request.SnapshotHash, PreviousSnapshotHash: request.PreviousSnapshotHash, DefinitionCount: len(request.Definitions)}
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
		next, err := persistence.Encode(binding.namespace(), "permissions", key, string(request.Application.WorkspaceID), "", identity.PermissionSourceSnapshot{WorkspaceID: request.Application.WorkspaceID, SourceOwner: request.SourceOwner, SnapshotHash: request.SnapshotHash, Definitions: request.Definitions})
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
			} else if old == definition {
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
	if err := binding.checkApplication(catalog.Application); err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	if err := validateRoleCatalog(catalog); err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	if err := validateRoleSelection(catalog, binding.Config.PersonalWorkspace.InitialRoleKeys, false); err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	for _, subject := range binding.Config.ServiceSubjects {
		if err := validateRoleSelection(catalog, subject.RoleKeys, true); err != nil {
			return identity.ProjectRoleCatalogReceipt{}, err
		}
	}
	if err := binding.saveCatalog(ctx, "roles", "", catalog); err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	encoded, err := persistence.Encode(binding.namespace(), "roles", "", "", "", catalog)
	if err != nil {
		return identity.ProjectRoleCatalogReceipt{}, err
	}
	return identity.ProjectRoleCatalogReceipt{Published: len(catalog.Roles), SHA256: encoded.Revision}, nil
}

func (binding *Binding) roles(ctx context.Context, db sqlhost.DBTX) (identity.ProjectRoleCatalog, error) {
	record, found, err := binding.Store.Get(ctx, db, binding.catalogKey("roles", ""))
	if err != nil {
		return identity.ProjectRoleCatalog{}, err
	}
	if !found {
		return identity.ProjectRoleCatalog{}, fmt.Errorf("external identity project roles have not been published")
	}
	var catalog identity.ProjectRoleCatalog
	err = json.Unmarshal(record.Payload, &catalog)
	return catalog, err
}

func (binding *Binding) validateAssignedRoles(ctx context.Context, db sqlhost.DBTX, keys []string, service bool) error {
	catalog, err := binding.roles(ctx, db)
	if err != nil {
		return err
	}
	return validateRoleSelection(catalog, keys, service)
}

var _ identity.PermissionSnapshotReader = (*Binding)(nil)
