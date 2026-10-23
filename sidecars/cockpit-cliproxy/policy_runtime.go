package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

type routingPolicySnapshot struct {
	revision string
	strategy string
	rules    []customRoutingRule
}

type routingPolicyRuntime struct {
	// Startup fields include unknown JSON keys. Only the two policy fields may differ.
	startupFields map[string]any
	active        atomic.Pointer[routingPolicySnapshot]
}

type policyRuntimeView struct {
	PersistedRevision string  `json:"persistedRevision"`
	ActiveRevision    *string `json:"activeRevision"`
	ApplySupported    bool    `json:"applySupported"`
	BlockedReason     *string `json:"blockedReason"`
}

const routingPolicyContextKey contextKey = "cockpitRoutingPolicySnapshot"

func policyManifestFields(data []byte) (map[string]any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var fields map[string]any
	if decoder.Decode(&fields) != nil || fields == nil {
		return nil, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, false
	}
	return fields, true
}

func nonPolicyFields(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		if key != "routingStrategy" && key != "customRoutingRules" {
			out[key] = value
		}
	}
	return out
}

func captureRoutingPolicyRuntime(m *manifest, data []byte) {
	fields, ok := policyManifestFields(data)
	if !ok {
		return
	}
	m.routingPolicy = &routingPolicyRuntime{startupFields: nonPolicyFields(fields)}
	m.routingPolicy.active.Store(&routingPolicySnapshot{
		revision: manifestETag(data), strategy: m.RoutingStrategy,
		rules: append([]customRoutingRule(nil), m.CustomRoutingRules...),
	})
}

func routingPolicyForContext(ctx context.Context, m *manifest) *routingPolicySnapshot {
	if ctx != nil {
		if snapshot, ok := ctx.Value(routingPolicyContextKey).(*routingPolicySnapshot); ok {
			return snapshot
		}
	}
	if m == nil {
		return &routingPolicySnapshot{}
	}
	if m.routingPolicy != nil {
		return m.routingPolicy.active.Load()
	}
	return &routingPolicySnapshot{strategy: m.RoutingStrategy, rules: m.CustomRoutingRules}
}

func withRoutingPolicySnapshot(ctx context.Context, m *manifest) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Value(routingPolicyContextKey) != nil {
		return ctx
	}
	return context.WithValue(ctx, routingPolicyContextKey, routingPolicyForContext(ctx, m))
}

var policyAccountID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func validateRoutingPolicy(fields map[string]any) (*routingPolicySnapshot, bool) {
	strategy := "auto"
	if value, exists := fields["routingStrategy"]; exists {
		var ok bool
		strategy, ok = value.(string)
		if !ok {
			return nil, false
		}
	}
	switch strategy {
	case "auto", "random", "quota_high_first", "quota_low_first", "plan_high_first", "plan_low_first", "expiry_soon_first", "custom":
	default:
		return nil, false
	}
	accounts, ok := fields["accounts"].([]any)
	if !ok || len(accounts) < 1 || len(accounts) > 256 {
		return nil, false
	}
	ids := make(map[string]bool, len(accounts))
	for _, value := range accounts {
		account, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		id, ok := account["id"].(string)
		if !ok || !policyAccountID.MatchString(id) || ids[id] {
			return nil, false
		}
		if kind, exists := account["authKind"]; exists && kind != "" && kind != "oauth" {
			return nil, false
		}
		ids[id] = true
	}
	snapshot := &routingPolicySnapshot{strategy: strategy}
	if fields["customRoutingRules"] == nil {
		return snapshot, true
	}
	rules, ok := fields["customRoutingRules"].([]any)
	if !ok || len(rules) > 256 {
		return nil, false
	}
	seen := make(map[string]bool, len(rules))
	for _, value := range rules {
		raw, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		id, ok := raw["accountId"].(string)
		if !ok || !ids[id] || seen[id] {
			return nil, false
		}
		rule := customRoutingRule{AccountID: id, Weight: 1}
		for _, field := range []struct {
			name   string
			target *int
			min    int
		}{
			{"priority", &rule.Priority, -10000}, {"weight", &rule.Weight, 1},
		} {
			if value, exists := raw[field.name]; exists {
				number, ok := value.(json.Number)
				if !ok {
					return nil, false
				}
				n, err := strconv.Atoi(string(number))
				if err != nil || n < field.min || n > 10000 {
					return nil, false
				}
				*field.target = n
			}
		}
		for _, field := range []struct {
			name   string
			target *bool
		}{
			{"isBackup", &rule.IsBackup}, {"isPreferred", &rule.IsPreferred},
		} {
			if value, exists := raw[field.name]; exists {
				flag, ok := value.(bool)
				if !ok {
					return nil, false
				}
				*field.target = flag
			}
		}
		if rule.IsBackup && rule.IsPreferred {
			return nil, false
		}
		snapshot.rules = append(snapshot.rules, rule)
		seen[id] = true
	}
	return snapshot, true
}

func (s *relayServer) policyRuntimeStatus(data []byte, revision string) (policyRuntimeView, *routingPolicySnapshot) {
	view := policyRuntimeView{PersistedRevision: revision}
	reason := "runtime_unavailable"
	if s.manifest != nil && s.manifest.routingPolicy != nil {
		runtime := s.manifest.routingPolicy
		view.ActiveRevision = &runtime.active.Load().revision
		fields, ok := policyManifestFields(data)
		reason = "unsupported_policy"
		if ok {
			if !reflect.DeepEqual(runtime.startupFields, nonPolicyFields(fields)) {
				reason = "non_policy_change"
			} else if candidate, valid := validateRoutingPolicy(fields); valid {
				candidate.revision = revision
				view.ApplySupported = true
				return view, candidate
			}
		}
	}
	view.BlockedReason = &reason
	return view, nil
}

func (s *relayServer) handleGetPolicyRuntime(c *gin.Context)   { s.handlePolicyRuntime(c, false) }
func (s *relayServer) handleApplyPolicyRuntime(c *gin.Context) { s.handlePolicyRuntime(c, true) }

func (s *relayServer) handlePolicyRuntime(c *gin.Context, apply bool) {
	c.Header("Cache-Control", "no-store")
	if !s.requireAdminToken(c) {
		return
	}
	expected := strings.TrimSpace(c.GetHeader("If-Match"))
	if apply && expected == "" {
		writeAPIError(c, http.StatusPreconditionRequired, "policy apply requires If-Match", "if_match_required")
		return
	}
	if s.manifestAdmin == nil {
		writeAPIError(c, http.StatusServiceUnavailable, "policy runtime unavailable", "runtime_unavailable")
		return
	}
	// The manifest admin PUT uses this same mutex: save/check/apply is one operation.
	s.manifestAdmin.mu.Lock()
	defer s.manifestAdmin.mu.Unlock()
	data, revision, err := s.manifestAdmin.read()
	if err != nil {
		writeAPIError(c, http.StatusServiceUnavailable, "policy runtime unavailable", "runtime_unavailable")
		return
	}
	if apply && expected != revision {
		writeAPIError(c, http.StatusPreconditionFailed, "manifest changed since it was read", "manifest_changed")
		return
	}
	view, candidate := s.policyRuntimeStatus(data, revision)
	if apply {
		if !view.ApplySupported {
			status := http.StatusUnprocessableEntity
			if *view.BlockedReason == "runtime_unavailable" {
				status = http.StatusServiceUnavailable
			}
			writeAPIError(c, status, "policy cannot be applied", *view.BlockedReason)
			return
		}
		s.manifest.routingPolicy.active.Store(candidate)
		view.ActiveRevision = &candidate.revision
	}
	c.JSON(http.StatusOK, view)
}
