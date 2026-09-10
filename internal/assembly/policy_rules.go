package assembly

import (
	"encoding/json"
	"fmt"
	"strings"

	identity "github.com/domainry/domainry-identity-sdk"
)

type expression struct {
	Operator    string       `json:"operator"`
	FieldKey    string       `json:"field_key"`
	Values      []string     `json:"values"`
	ValueSource string       `json:"value_source"`
	ClaimKey    string       `json:"claim_key"`
	Children    []expression `json:"children"`
	Path        []struct {
		Direction string `json:"direction"`
		Reference string `json:"relation_field_key"`
		Target    string `json:"target_object_key"`
	} `json:"path"`
}
type fieldRule struct {
	Key          string                 `json:"key"`
	Priority     int                    `json:"priority"`
	Actions      []identity.Action      `json:"actions"`
	Effect       identity.FieldEffect   `json:"effect"`
	Predicate    *expression            `json:"predicate"`
	MaskStrategy *identity.MaskStrategy `json:"mask_strategy"`
	AuditDenial  bool                   `json:"audit_denial"`
}

func convertFieldRules(role string, rules []fieldRule) ([]identity.FieldRule, error) {
	result := []identity.FieldRule{}
	for _, rule := range rules {
		value := identity.FieldRule{Key: role + ":" + rule.Key, Priority: rule.Priority, Actions: rule.Actions, Effect: rule.Effect, MaskStrategy: rule.MaskStrategy, AuditDenial: rule.AuditDenial}
		if rule.Predicate != nil {
			predicate, err := convertExpression(*rule.Predicate)
			if err != nil {
				return nil, err
			}
			value.Predicate = &predicate
		}
		result = append(result, value)
	}
	return result, nil
}

func convertExpression(value expression) (identity.Predicate, error) {
	result := identity.Predicate{}
	switch value.Operator {
	case "and", "or":
		for _, child := range value.Children {
			predicate, err := convertExpression(child)
			if err != nil {
				return result, err
			}
			if value.Operator == "and" {
				result.All = append(result.All, predicate)
			} else {
				result.Any = append(result.Any, predicate)
			}
		}
	case "not":
		if len(value.Children) != 1 {
			return result, fmt.Errorf("not policy requires one child")
		}
		predicate, err := convertExpression(value.Children[0])
		if err != nil {
			return result, err
		}
		result.Not = &predicate
	case "eq", "in":
		result.Fact = value.FieldKey
		result.Operator = identity.Operator(value.Operator)
		if value.ValueSource == "actor_claim" {
			switch value.ClaimKey {
			case "user_id", "subject_id", "id":
				result.Value = "$subject.id"
			case "org_id", "org_scope_ids", "reporting_scope_user_ids", "support_org_scope_ids":
				result.Value = "$subject." + value.ClaimKey
			case "business_profile_id":
				result.Value = "$context.business_profile_id"
			default:
				result.Value = "$context.claims." + value.ClaimKey
			}
		} else {
			if value.ValueSource != "" && value.ValueSource != "literal" {
				return result, fmt.Errorf("unsupported policy value source")
			}
			if value.Operator == "eq" && len(value.Values) == 1 {
				result.Value = value.Values[0]
			} else {
				result.Value = value.Values
			}
		}
		for _, segment := range value.Path {
			result.Path = append(result.Path, identity.RelationSegment{Direction: identity.RelationDirection(segment.Direction), Reference: segment.Reference, TargetResource: identity.ResourceType(segment.Target)})
		}
	default:
		return result, fmt.Errorf("unsupported field policy operator %q", value.Operator)
	}
	return result, result.Validate()
}

type guardrailDefinition struct {
	Key    string   `json:"key"`
	Denied []string `json:"denied_permission_keys"`
	Data   []struct {
		Object  string   `json:"object_key"`
		Actions []string `json:"actions"`
		Reason  string   `json:"reason"`
	} `json:"data_restrictions"`
	Fields []struct {
		Object  string   `json:"object_key"`
		Field   string   `json:"field_key"`
		Actions []string `json:"actions"`
		Reason  string   `json:"reason"`
	} `json:"field_restrictions"`
}

func compileGuardrails(role identity.ProjectRoleDefinition) ([]identity.Guardrail, error) {
	var definitions []guardrailDefinition
	if len(role.Guardrails) > 0 {
		if err := json.Unmarshal(role.Guardrails, &definitions); err != nil {
			return nil, err
		}
	}
	known := map[string]bool{}
	result := []identity.Guardrail{}
	for _, guardrail := range definitions {
		known[guardrail.Key] = true
		if !includes(role.GuardrailKeys, guardrail.Key) {
			continue
		}
		prefix := role.Key + ":" + guardrail.Key
		for _, permission := range guardrail.Denied {
			index := strings.LastIndexByte(permission, '.')
			if index <= 0 {
				return nil, fmt.Errorf("invalid guardrail permission")
			}
			result = append(result, identity.Guardrail{Key: prefix + ":permission:" + permission, Resource: identity.ResourceType(permission[:index]), Action: identity.Action(permission[index+1:]), Effect: identity.EffectDeny})
		}
		for _, restriction := range guardrail.Data {
			for _, action := range restriction.Actions {
				result = append(result, identity.Guardrail{Key: prefix + ":data:" + restriction.Object + ":" + action, Resource: identity.ResourceType(restriction.Object), Action: identity.Action(action), Effect: identity.EffectDeny, Reason: restriction.Reason})
			}
		}
		for _, restriction := range guardrail.Fields {
			for _, action := range restriction.Actions {
				result = append(result, identity.Guardrail{Key: prefix + ":field:" + restriction.Object + ":" + restriction.Field + ":" + action, Resource: identity.ResourceType(restriction.Object), Action: identity.Action(action), Field: restriction.Field, Effect: identity.EffectDeny, Reason: restriction.Reason})
			}
		}
	}
	for _, key := range role.GuardrailKeys {
		if !known[key] {
			return nil, fmt.Errorf("unresolved role guardrail %q", key)
		}
	}
	return result, nil
}
