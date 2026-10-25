package moduleassembly

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/domainry/domainry-foundation/entityid"
	bridge "github.com/domainry/domainry-identity-bridge/internal/domain/bridge"
	"github.com/domainry/domainry-identity-bridge/internal/persistence"
	identity "github.com/domainry/domainry-identity-sdk"
)

type workspaceState struct {
	InstallationID      string `json:"installation_id"`
	ProviderKey         string `json:"provider_key"`
	ExternalWorkspaceID string `json:"external_workspace_id"`
	WorkspaceID         string `json:"workspace_id"`
	Active              bool   `json:"active"`
}

type membership struct {
	Binding bridge.WorkspaceBinding `json:"binding"`
	User    identity.User           `json:"user"`
}

type assignment struct {
	RoleKeys []string `json:"role_keys"`
	Active   bool     `json:"active"`
}

type applicationBootstrap struct {
	Active bool `json:"active"`
}

func opaque(prefix string) (string, error) {
	return entityid.New(prefix)
}

func (binding *Binding) ResolveWorkspace(ctx context.Context, request bridge.WorkspaceRequest) (bridge.WorkspaceBinding, error) {
	if request.InstallationID != binding.Config.InstallationID || request.ApplicationKey != binding.Config.ApplicationKey || request.ProviderKey != binding.Config.Provider.Key || request.ExternalWorkspaceID == "" || request.ExternalSubjectID == "" {
		return bridge.WorkspaceBinding{}, denied()
	}
	workspaceKey := persistence.Key(binding.namespace(), "workspace", request.ExternalWorkspaceID)
	memberKey := persistence.Key(binding.namespace(), "member", request.ExternalWorkspaceID, request.ExternalSubjectID)
	var state workspaceState
	var result membership
	apply := func(ctx context.Context, transaction identity.EmbeddedTransaction) error {
		workspaceRecord, workspaceFound, err := binding.Store.Get(ctx, transaction.Executor, workspaceKey)
		if err != nil {
			return err
		}
		if workspaceFound {
			if err := json.Unmarshal(workspaceRecord.Payload, &state); err != nil {
				return err
			}
			if state.InstallationID != request.InstallationID || state.ProviderKey != request.ProviderKey || state.ExternalWorkspaceID != request.ExternalWorkspaceID || state.WorkspaceID == "" {
				return denied()
			}
			if !state.Active {
				return bridge.ErrWorkspaceInactive
			}
		} else {
			if !request.CreateIfMissing {
				return bridge.ErrWorkspaceUnavailable
			}
			workspaceID, err := opaque("ws")
			if err != nil {
				return err
			}
			state = workspaceState{InstallationID: request.InstallationID, ProviderKey: request.ProviderKey, ExternalWorkspaceID: request.ExternalWorkspaceID, WorkspaceID: workspaceID, Active: true}
			workspaceRecord, err = persistence.Encode(binding.namespace(), "workspace", workspaceKey, workspaceID, workspaceID, state)
			if err != nil {
				return err
			}
			// Claim the external Workspace before any Runtime-owned row is created.
			// A concurrent loser retries the whole host transaction and joins it.
			if err := binding.Store.Insert(ctx, transaction.Executor, workspaceRecord); err != nil {
				return err
			}
		}

		memberRecord, memberFound, err := binding.Store.Get(ctx, transaction.Executor, memberKey)
		if err != nil {
			return err
		}
		if memberFound {
			if err := json.Unmarshal(memberRecord.Payload, &result); err != nil {
				return err
			}
			if !sameMembership(result.Binding, request, state.WorkspaceID) {
				return denied()
			}
			if !result.Binding.Active {
				return bridge.ErrWorkspaceInactive
			}
			if result.User.Name != request.DisplayName || result.User.Email != request.Email {
				result.User.Name, result.User.Email = request.DisplayName, request.Email
				next, err := persistence.Encode(binding.namespace(), "member", memberKey, state.WorkspaceID, result.Binding.UserID, result)
				if err != nil {
					return err
				}
				if err := binding.Store.CompareAndSwap(ctx, transaction.Executor, next, memberRecord.Revision); err != nil {
					return err
				}
			}
		} else {
			if !request.CreateIfMissing {
				return bridge.ErrWorkspaceUnavailable
			}
			userID, err := opaque("user")
			if err != nil {
				return err
			}
			result = membership{Binding: bridge.WorkspaceBinding{
				InstallationID: request.InstallationID, ProviderKey: request.ProviderKey,
				ExternalWorkspaceID: request.ExternalWorkspaceID, ExternalSubjectID: request.ExternalSubjectID,
				WorkspaceID: state.WorkspaceID, UserID: userID, Active: true,
			}, User: identity.User{UserID: userID, Name: request.DisplayName, Email: request.Email, Status: "active"}}
			memberRecord, err = persistence.Encode(binding.namespace(), "member", memberKey, state.WorkspaceID, userID, result)
			if err != nil {
				return err
			}
			if err := binding.Store.Insert(ctx, transaction.Executor, memberRecord); err != nil {
				return err
			}
		}

		if !workspaceFound {
			if err := binding.Store.Host.CreateExternalWorkspace(ctx, identity.ExternalWorkspaceCreate{
				WorkspaceID: state.WorkspaceID, UserID: result.Binding.UserID, Name: request.Name,
				ApplicationBootstrap: binding.Config.Workspace.ApplicationBootstrap,
			}, transaction); err != nil {
				return err
			}
		}

		bootstrapKey := binding.catalogKey("bootstrap", workspaceKey)
		if _, found, err := binding.Store.Get(ctx, transaction.Executor, bootstrapKey); err != nil {
			return err
		} else if !found {
			if !request.CreateIfMissing {
				return bridge.ErrWorkspaceUnavailable
			}
			if err := binding.Store.Host.InitializeExternalWorkspaceApplication(ctx, identity.ExternalWorkspaceCreate{
				WorkspaceID: state.WorkspaceID, UserID: result.Binding.UserID, Name: request.Name,
				ApplicationBootstrap: binding.Config.Workspace.ApplicationBootstrap,
			}, transaction); err != nil {
				return err
			}
			record, err := persistence.Encode(binding.namespace(), "bootstrap", bootstrapKey, state.WorkspaceID, result.Binding.UserID, applicationBootstrap{Active: true})
			if err != nil {
				return err
			}
			if err := binding.Store.Insert(ctx, transaction.Executor, record); err != nil {
				return err
			}
		}

		assignmentKey := binding.catalogKey("assignment", memberKey)
		if _, found, err := binding.Store.Get(ctx, transaction.Executor, assignmentKey); err != nil {
			return err
		} else if !found {
			if !request.CreateIfMissing {
				return bridge.ErrWorkspaceUnavailable
			}
			if err := binding.validateAssignedRoles(ctx, transaction.Executor, request.InitialRoleKeys, false); err != nil {
				return err
			}
			record, err := persistence.Encode(binding.namespace(), "assignment", assignmentKey, state.WorkspaceID, result.Binding.UserID, assignment{RoleKeys: append([]string(nil), request.InitialRoleKeys...), Active: true})
			if err != nil {
				return err
			}
			if err := binding.Store.Insert(ctx, transaction.Executor, record); err != nil {
				return err
			}
		}
		return nil
	}
	if err := binding.Store.Host.RunExternalWorkspaceTransaction(ctx, apply); err != nil {
		return bridge.WorkspaceBinding{}, err
	}
	if !sameMembership(result.Binding, request, state.WorkspaceID) {
		return bridge.WorkspaceBinding{}, denied()
	}
	active, err := binding.Store.Host.ExternalWorkspaceActive(ctx, result.Binding.WorkspaceID)
	if err != nil {
		return bridge.WorkspaceBinding{}, err
	}
	result.Binding.Active = result.Binding.Active && state.Active && active
	return result.Binding, nil
}

func sameMembership(value bridge.WorkspaceBinding, request bridge.WorkspaceRequest, workspaceID string) bool {
	return value.InstallationID == request.InstallationID && value.ProviderKey == request.ProviderKey &&
		value.ExternalWorkspaceID == request.ExternalWorkspaceID && value.ExternalSubjectID == request.ExternalSubjectID &&
		value.WorkspaceID == workspaceID && value.UserID != ""
}

func (binding *Binding) memberForUser(ctx context.Context, workspace, user string) (membership, error) {
	if workspace == "" || user == "" {
		return membership{}, denied()
	}
	records, err := binding.Store.List(ctx, binding.namespace(), "member", workspace)
	if err != nil {
		return membership{}, err
	}
	for _, record := range records {
		if record.SubjectID == user {
			var value membership
			if err := json.Unmarshal(record.Payload, &value); err != nil {
				return membership{}, err
			}
			if !value.Binding.Active {
				return membership{}, denied()
			}
			return value, nil
		}
	}
	return membership{}, fmt.Errorf("external identity subject is not provisioned")
}
