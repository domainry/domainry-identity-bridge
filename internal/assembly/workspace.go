package assembly

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	bridge "github.com/domainry/domainry-identity-bridge"
	"github.com/domainry/domainry-identity-bridge/internal/persistence"
	identity "github.com/domainry/domainry-identity-sdk"
)

type ownership struct {
	Binding bridge.WorkspaceBinding `json:"binding"`
	User    identity.User           `json:"user"`
}
type assignment struct {
	RoleKeys []string `json:"role_keys"`
	Active   bool     `json:"active"`
}

func opaque(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}

func (binding *Binding) ResolvePersonalWorkspace(ctx context.Context, request bridge.PersonalWorkspaceRequest) (bridge.WorkspaceBinding, error) {
	if request.InstallationID != binding.Config.InstallationID || request.ApplicationKey != binding.Config.ApplicationKey || request.ProviderKey != binding.Config.Provider.Key || request.ExternalSubjectID == "" {
		return bridge.WorkspaceBinding{}, denied()
	}
	key := persistence.Key(binding.namespace(), "owner", request.ExternalSubjectID)
	var result ownership
	apply := func(ctx context.Context, transaction identity.EmbeddedTransaction) error {
		record, found, err := binding.Store.Get(ctx, transaction.Executor, key)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(record.Payload, &result); err != nil {
				return err
			}
			if result.Binding.InstallationID != request.InstallationID || result.Binding.ProviderKey != request.ProviderKey || result.Binding.ExternalSubjectID != request.ExternalSubjectID {
				return denied()
			}
			if !result.Binding.Active {
				return bridge.ErrWorkspaceInactive
			}
			if result.User.Name != request.DisplayName || result.User.Email != request.Email {
				result.User.Name, result.User.Email = request.DisplayName, request.Email
				next, err := persistence.Encode(binding.namespace(), "owner", key, result.Binding.WorkspaceID, result.Binding.UserID, result)
				if err != nil {
					return err
				}
				if err := binding.Store.CompareAndSwap(ctx, transaction.Executor, next, record.Revision); err != nil {
					return err
				}
			}
		} else {
			if !request.CreateIfMissing {
				return bridge.ErrWorkspaceUnavailable
			}
			workspace, err := opaque("workspace")
			if err != nil {
				return err
			}
			user, err := opaque("user")
			if err != nil {
				return err
			}
			result = ownership{Binding: bridge.WorkspaceBinding{InstallationID: request.InstallationID, ProviderKey: request.ProviderKey, ExternalSubjectID: request.ExternalSubjectID, WorkspaceID: workspace, UserID: user, Active: true}, User: identity.User{ID: user, Name: request.DisplayName, Email: request.Email, Status: "active"}}
			record, err := persistence.Encode(binding.namespace(), "owner", key, workspace, user, result)
			if err != nil {
				return err
			}
			// Claim the unique owner before creating host data. A losing concurrent
			// transaction cannot leave an orphan Workspace behind.
			if err := binding.Store.Insert(ctx, transaction.Executor, record); err != nil {
				return err
			}
			if err := binding.Store.Host.CreateExternalWorkspace(ctx, identity.ExternalWorkspaceCreate{WorkspaceID: workspace, UserID: user, Name: request.Name, ApplicationBootstrap: binding.Config.PersonalWorkspace.ApplicationBootstrap}, transaction); err != nil {
				return err
			}
		}
		assignmentKey := binding.catalogKey("assignment", key)
		if _, found, err := binding.Store.Get(ctx, transaction.Executor, assignmentKey); err != nil {
			return err
		} else if !found {
			if !request.CreateIfMissing {
				return bridge.ErrWorkspaceUnavailable
			}
			if err := binding.Store.Host.InitializeExternalWorkspaceApplication(ctx, identity.ExternalWorkspaceCreate{WorkspaceID: result.Binding.WorkspaceID, UserID: result.Binding.UserID, Name: request.Name, ApplicationBootstrap: binding.Config.PersonalWorkspace.ApplicationBootstrap}, transaction); err != nil {
				return err
			}
			if err := binding.validateAssignedRoles(ctx, transaction.Executor, request.InitialRoleKeys, false); err != nil {
				return err
			}
			record, err := persistence.Encode(binding.namespace(), "assignment", assignmentKey, result.Binding.WorkspaceID, result.Binding.UserID, assignment{RoleKeys: append([]string(nil), request.InitialRoleKeys...), Active: true})
			if err != nil {
				return err
			}
			if err := binding.Store.Insert(ctx, transaction.Executor, record); err != nil {
				return err
			}
		}
		return nil
	}
	err := binding.Store.Host.RunExternalWorkspaceTransaction(ctx, apply)
	if err != nil {
		return bridge.WorkspaceBinding{}, err
	}

	if result.Binding.InstallationID != request.InstallationID || result.Binding.ProviderKey != request.ProviderKey || result.Binding.ExternalSubjectID != request.ExternalSubjectID {
		return bridge.WorkspaceBinding{}, denied()
	}
	active, err := binding.Store.Host.ExternalWorkspaceActive(ctx, result.Binding.WorkspaceID)
	if err != nil {
		return bridge.WorkspaceBinding{}, err
	}
	result.Binding.Active = result.Binding.Active && active
	return result.Binding, nil
}

func (binding *Binding) ownerForUser(ctx context.Context, workspace, user string) (ownership, error) {
	if workspace == "" || user == "" {
		return ownership{}, denied()
	}
	records, err := binding.Store.List(ctx, binding.namespace(), "owner", workspace)
	if err != nil {
		return ownership{}, err
	}
	for _, record := range records {
		if record.SubjectID == user {
			var value ownership
			if err := json.Unmarshal(record.Payload, &value); err != nil {
				return ownership{}, err
			}
			if !value.Binding.Active {
				return ownership{}, denied()
			}
			return value, nil
		}
	}
	return ownership{}, fmt.Errorf("external identity subject is not provisioned")
}
