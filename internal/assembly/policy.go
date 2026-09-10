package assembly

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	bridge "github.com/domainry/domainry-identity-bridge"
	"github.com/domainry/domainry-identity-bridge/internal/persistence"
	identity "github.com/domainry/domainry-identity-sdk"
	"github.com/domainry/domainry-identity-sdk/authorization/evaluator"
)

type objectFields struct {
	Key    string `json:"key"`
	Fields []struct {
		Key      string `json:"key"`
		ReadOnly bool   `json:"read_only"`
	} `json:"fields"`
}
type fieldPermission struct {
	ObjectKey string      `json:"object_key"`
	FieldKey  string      `json:"field_key"`
	Read      bool        `json:"read"`
	Write     bool        `json:"write"`
	Export    bool        `json:"export"`
	Masked    bool        `json:"masked"`
	Reason    string      `json:"reason"`
	Policies  []fieldRule `json:"policies"`
}
type referencePermission struct {
	Source string   `json:"source_object_key"`
	Field  string   `json:"relation_field_key"`
	Target string   `json:"target_object_key"`
	Fields []string `json:"display_fields"`
	Mode   string   `json:"mode"`
	Reason string   `json:"reason"`
}
type exportRule struct {
	Object string   `json:"object_key"`
	Mode   string   `json:"mode"`
	Fields []string `json:"fields"`
}

func validateRoleCatalog(catalog identity.ProjectRoleCatalog) error {
	seen := map[string]bool{}
	for _, role := range catalog.Roles {
		if role.Key == "" || seen[role.Key] || role.Name == "" {
			return fmt.Errorf("invalid or duplicate external project role")
		}
		seen[role.Key] = true
		grants := map[string]bool{}
		for _, grant := range role.Permissions {
			if !grant.DataScope.Valid() || grant.PermissionKey == "" || grants[grant.PermissionKey] {
				return fmt.Errorf("invalid external role grant")
			}
			grants[grant.PermissionKey] = true
		}
		if len(role.PermissionSetKeys) > 0 || len(role.PermissionSetGroups) > 0 || role.RequiredBindingKey != "" {
			return fmt.Errorf("external role %q requires unresolved permission sets or profile binding", role.Key)
		}
		if _, err := compileRoles(catalog, []string{role.Key}, identity.Subject{WorkspaceID: "validation", SubjectID: "validation"}, "validation", time.Now().UTC()); err != nil {
			return fmt.Errorf("external role %q: %w", role.Key, err)
		}
	}
	return nil
}

func validateRoleSelection(catalog identity.ProjectRoleCatalog, keys []string, service bool) error {
	if len(keys) == 0 {
		return denied()
	}
	roles := map[string]identity.ProjectRoleDefinition{}
	for _, role := range catalog.Roles {
		roles[role.Key] = role
	}
	selected := map[string]bool{}
	for _, key := range keys {
		if selected[key] {
			return denied()
		}
		selected[key] = true
	}
	for _, key := range keys {
		role, found := roles[key]
		if !found {
			return fmt.Errorf("external identity role %q is not published", key)
		}
		if service {
			if role.Audience != "service" || role.AssignmentMode != "system_managed" {
				return denied()
			}
		} else {
			if !role.ProvisionToWorkspaces || (role.Audience != "" && role.Audience != "any" && role.Audience != "user") || (role.AssignmentMode != "" && role.AssignmentMode != "manual") {
				return denied()
			}
			for _, grant := range role.Permissions {
				if strings.HasPrefix(grant.PermissionKey, "runtime.workspaceprovision.") || strings.HasPrefix(grant.PermissionKey, "runtime.operations.") {
					return fmt.Errorf("personal role cannot grant installation administration")
				}
			}
		}
		for _, conflict := range role.ConflictRoleKeys {
			if selected[conflict] {
				return denied()
			}
		}
	}
	return nil
}

func (binding *Binding) assignment(ctx context.Context, owner ownership) (assignment, error) {
	key := persistence.Key(binding.namespace(), "owner", owner.Binding.ExternalSubjectID)
	record, found, err := binding.Store.Get(ctx, binding.Store.DB, binding.catalogKey("assignment", key))
	if err != nil {
		return assignment{}, err
	}
	if !found {
		return assignment{}, denied()
	}
	var value assignment
	if err := json.Unmarshal(record.Payload, &value); err != nil {
		return assignment{}, err
	}
	if !value.Active {
		return assignment{}, denied()
	}
	return value, nil
}

func (binding *Binding) assignedRoles(ctx context.Context, workspace, user string) ([]identity.Role, error) {
	owner, err := binding.ownerForUser(ctx, workspace, user)
	if err != nil {
		return nil, err
	}
	assignment, err := binding.assignment(ctx, owner)
	if err != nil {
		return nil, err
	}
	catalog, err := binding.roles(ctx, binding.Store.DB)
	if err != nil {
		return nil, err
	}
	roles := []identity.Role{}
	for _, key := range assignment.RoleKeys {
		for _, role := range catalog.Roles {
			if role.Key == key {
				roles = append(roles, identity.Role{ID: role.Key, Key: role.Key, Label: role.Name, Status: "active"})
			}
		}
	}
	return roles, nil
}

func (binding *Binding) ResolveAccess(ctx context.Context, request bridge.PolicyRequest) (identity.AccessBundle, error) {
	if request.ApplicationKey != binding.Config.ApplicationKey {
		return identity.AccessBundle{}, denied()
	}
	owner, err := binding.ownerForUser(ctx, request.Workspace.WorkspaceID, request.Workspace.UserID)
	if err != nil {
		return identity.AccessBundle{}, err
	}
	if owner.Binding.ProviderKey != request.Workspace.ProviderKey || owner.Binding.ExternalSubjectID != request.Workspace.ExternalSubjectID {
		return identity.AccessBundle{}, denied()
	}
	assigned, err := binding.assignment(ctx, owner)
	if err != nil {
		return identity.AccessBundle{}, err
	}
	return binding.bundle(ctx, owner.Binding.WorkspaceID, owner.Binding.UserID, assigned.RoleKeys, false)
}

func (binding *Binding) bundle(ctx context.Context, workspace, user string, keys []string, service bool) (identity.AccessBundle, error) {
	active, err := binding.Store.Host.ExternalWorkspaceActive(ctx, workspace)
	if err != nil {
		return identity.AccessBundle{}, err
	}
	if !active {
		return identity.AccessBundle{}, denied()
	}
	catalog, err := binding.roles(ctx, binding.Store.DB)
	if err != nil {
		return identity.AccessBundle{}, err
	}
	if err := validateRoleSelection(catalog, keys, service); err != nil {
		return identity.AccessBundle{}, err
	}
	registries, err := binding.Store.List(ctx, binding.namespace(), "permissions", string(binding.Application.WorkspaceID))
	if err != nil {
		return identity.AccessBundle{}, err
	}
	known := map[string]bool{}
	for _, record := range registries {
		var snapshot identity.PermissionSourceSnapshot
		if err := json.Unmarshal(record.Payload, &snapshot); err != nil {
			return identity.AccessBundle{}, err
		}
		// The state key binds source owner to this exact application.
		if record.Key != binding.catalogKey("permissions", snapshot.SourceOwner) {
			continue
		}
		for _, definition := range snapshot.Definitions {
			known[definition.PermissionKey] = true
		}
	}
	for _, role := range catalog.Roles {
		if includes(keys, role.Key) {
			for _, grant := range role.Permissions {
				if !known[grant.PermissionKey] {
					return identity.AccessBundle{}, fmt.Errorf("external role permission %q is not registered", grant.PermissionKey)
				}
			}
		}
	}
	raw, _ := json.Marshal(struct {
		Catalog identity.ProjectRoleCatalog
		Roles   []string
	}{catalog, keys})
	revision := persistence.Key(string(raw))
	return compileRoles(catalog, keys, identity.Subject{WorkspaceID: identity.WorkspaceID(workspace), SubjectID: identity.SubjectID(user)}, revision, binding.Now())
}

func compileRoles(catalog identity.ProjectRoleCatalog, keys []string, subject identity.Subject, revision string, now time.Time) (identity.AccessBundle, error) {
	bundle := identity.AccessBundle{ContractVersion: identity.CurrentPolicyBundleVersion, AuthorizationRevision: identity.AuthorizationRevision(revision), Subject: subject, ExpiresAt: now.Add(5 * time.Minute)}
	var objects []objectFields
	if len(catalog.Objects) > 0 {
		if err := json.Unmarshal(catalog.Objects, &objects); err != nil {
			return bundle, err
		}
	}
	functions := map[string]identity.FunctionGrant{}
	fields := map[string]identity.FieldPolicy{}
	references := map[string]identity.ReferencePolicy{}
	exports := map[string]identity.ExportPolicy{}
	for _, role := range catalog.Roles {
		if !includes(keys, role.Key) {
			continue
		}
		roleFunctions := map[string]bool{}
		for _, grant := range role.Permissions {
			at := strings.LastIndexByte(grant.PermissionKey, '.')
			if at <= 0 || at == len(grant.PermissionKey)-1 {
				return bundle, fmt.Errorf("invalid exact permission")
			}
			resource, action := grant.PermissionKey[:at], grant.PermissionKey[at+1:]
			roleFunctions[grant.PermissionKey] = true
			functions[grant.PermissionKey] = identity.FunctionGrant{Resource: identity.ResourceType(resource), Action: identity.Action(action), Effect: identity.EffectAllow}
			bundle.DataPolicies = append(bundle.DataPolicies, identity.DataPolicy{Key: role.Key + ":" + grant.PermissionKey, Resource: identity.ResourceType(resource), Action: identity.Action(action), Effect: identity.EffectAllow, DataScopes: []identity.DataScope{grant.DataScope}, Predicate: scopePredicate(grant.DataScope), AuditDenial: grant.AuditDenial})
		}
		localFields := map[string]identity.FieldPolicy{}
		for _, object := range objects {
			for _, field := range object.Fields {
				localFields[object.Key+"\x00"+field.Key] = identity.FieldPolicy{Resource: identity.ResourceType(object.Key), Field: field.Key, Read: roleFunctions[object.Key+".read"], Write: !field.ReadOnly && (roleFunctions[object.Key+".create"] || roleFunctions[object.Key+".update"]), Export: roleFunctions[object.Key+".export"]}
			}
		}
		var declared []fieldPermission
		if len(role.FieldPermissions) > 0 {
			if err := json.Unmarshal(role.FieldPermissions, &declared); err != nil {
				return bundle, err
			}
		}
		for _, field := range declared {
			rules, err := convertFieldRules(role.Key, field.Policies)
			if err != nil {
				return bundle, err
			}
			localFields[field.ObjectKey+"\x00"+field.FieldKey] = identity.FieldPolicy{Resource: identity.ResourceType(field.ObjectKey), Field: field.FieldKey, Read: field.Read, Write: field.Write, Export: field.Export, Masked: field.Masked, Reason: field.Reason, Rules: rules}
		}
		for key, field := range localFields {
			current := fields[key]
			if current.Field == "" {
				fields[key] = field
				continue
			}
			current.Read = current.Read || field.Read
			current.Write = current.Write || field.Write
			current.Export = current.Export || field.Export
			current.Masked = current.Masked || field.Masked
			current.Rules = append(current.Rules, field.Rules...)
			fields[key] = current
		}
		var refs []referencePermission
		if len(role.ReferencePermissions) > 0 {
			if err := json.Unmarshal(role.ReferencePermissions, &refs); err != nil {
				return bundle, err
			}
		}
		for _, ref := range refs {
			key := ref.Source + "\x00" + ref.Field
			value := identity.ReferencePolicy{SourceResource: identity.ResourceType(ref.Source), Reference: ref.Field, TargetResource: identity.ResourceType(ref.Target), DisplayFields: ref.Fields, Allowed: ref.Mode != "deny", Reason: ref.Reason}
			if previous, found := references[key]; found {
				value.Allowed = value.Allowed && previous.Allowed
				value.DisplayFields = unique(append(value.DisplayFields, previous.DisplayFields...))
			}
			references[key] = value
		}
		var exportRules []exportRule
		if len(role.ExportRules) > 0 {
			if err := json.Unmarshal(role.ExportRules, &exportRules); err != nil {
				return bundle, err
			}
		}
		for _, rule := range exportRules {
			if rule.Mode == "all_fields" {
				continue
			}
			mode := identity.ExportMode(rule.Mode)
			if rule.Mode == "selected_fields" {
				mode = identity.ExportModeAllowList
			}
			value := identity.ExportPolicy{Resource: identity.ResourceType(rule.Object), Mode: mode, Fields: rule.Fields}
			if old, ok := exports[rule.Object]; ok {
				if old.Mode == identity.ExportModeDeny || mode == identity.ExportModeDeny {
					value.Mode = identity.ExportModeDeny
					value.Fields = nil
				} else {
					value.Fields = unique(append(value.Fields, old.Fields...))
				}
			}
			exports[rule.Object] = value
		}
		guardrails, err := compileGuardrails(role)
		if err != nil {
			return bundle, err
		}
		bundle.Guardrails = append(bundle.Guardrails, guardrails...)
	}
	for _, key := range sortedKeys(functions) {
		bundle.FunctionGrants = append(bundle.FunctionGrants, functions[key])
	}
	for _, key := range sortedKeys(fields) {
		bundle.FieldPolicies = append(bundle.FieldPolicies, fields[key])
	}
	for _, key := range sortedKeys(references) {
		bundle.ReferencePolicies = append(bundle.ReferencePolicies, references[key])
	}
	for _, key := range sortedKeys(exports) {
		bundle.ExportPolicies = append(bundle.ExportPolicies, exports[key])
	}
	if err := bundle.Validate(now); err != nil {
		return identity.AccessBundle{}, err
	}
	return bundle, nil
}

func includes(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func unique(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if !includes(result, value) {
			result = append(result, value)
		}
	}
	return result
}
func sortedKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
func scopePredicate(scope identity.DataScope) identity.Predicate {
	switch scope {
	case identity.DataScopeAll:
		return identity.Predicate{}
	case identity.DataScopeOwner:
		return identity.Predicate{Fact: "owner_user_id", Operator: identity.OperatorEqual, Value: "$subject.id"}
	case identity.DataScopeOrg:
		return identity.Predicate{Fact: "owner_org_id", Operator: identity.OperatorEqual, Value: "$subject.org_id"}
	case identity.DataScopeOrgChild:
		return identity.Predicate{Fact: "owner_org_id", Operator: identity.OperatorIn, Value: "$subject.org_scope_ids"}
	case identity.DataScopeTargetOrg:
		return identity.Predicate{Fact: "owner_org_id", Operator: identity.OperatorIn, Value: "$subject.support_org_scope_ids"}
	default:
		return identity.Predicate{}
	}
}

type authorizationAdapter struct{ binding *Binding }

func (adapter authorizationAdapter) ResolveAccess(ctx context.Context, request identity.AccessBundleRequest) (identity.AccessBundle, error) {
	p, err := adapter.binding.Service.Authenticate(ctx, request.Identity.AccessToken)
	if err != nil {
		return identity.AccessBundle{}, err
	}
	if request.Identity.Principal.UserID != "" && (p.UserID != request.Identity.Principal.UserID || p.WorkspaceID != request.Identity.Principal.WorkspaceID) {
		return identity.AccessBundle{}, denied()
	}
	return *p.AccessBundle, nil
}
func (adapter authorizationAdapter) Reauthorize(ctx context.Context, request identity.DecisionRequest) (identity.AccessDecision, error) {
	bundle, err := adapter.ResolveAccess(ctx, identity.AccessBundleRequest{Identity: request.Identity})
	if err != nil {
		return identity.AccessDecision{}, err
	}
	decision, err := evaluator.Evaluate(bundle, request.Access, request.Facts, adapter.binding.Now())
	if err != nil {
		return identity.AccessDecision{}, err
	}
	effect := "deny"
	if decision.Allowed {
		effect = "allow"
	}
	return identity.AccessDecision{UserID: string(bundle.Subject.SubjectID), ObjectKey: request.Access.ObjectKey, Action: request.Access.Action, FieldKey: request.Access.FieldKey, RecordID: request.Access.RecordID, Allowed: decision.Allowed, AuthorizationRevision: string(bundle.AuthorizationRevision), Reason: identity.AccessReason{Code: decision.Code, Effect: effect, Layer: "authorization", Subject: string(bundle.Subject.SubjectID), Details: map[string]string{"policy_key": decision.PolicyKey, "reason": decision.Reason}}}, nil
}
