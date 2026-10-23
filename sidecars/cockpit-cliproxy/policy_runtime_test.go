package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const runtimePolicyFixture = `{"accounts":[{"id":"a","authId":"a.json","authKind":"oauth","planRank":3},{"id":"b","authId":"b.json","planRank":2},{"id":"c","authId":"c.json","planRank":1}],"apiKeys":[],"routingStrategy":"plan_high_first","customRoutingRules":[],"future":{"serial":9007199254740993}}`

func newRuntimePolicyTestServer(t *testing.T, data string) (*relayServer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	return &relayServer{manifest: m, policy: &requestPolicy{}, adminToken: "admin-secret", manifestAdmin: &manifestAdminStore{path: path}}, path
}

func policyRuntimeRequest(router http.Handler, method, token, revision string) *httptest.ResponseRecorder {
	path := "/admin/v1/policy-runtime"
	if method == http.MethodPost {
		path = "/admin/v1/policy-apply"
	}
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if revision != "" {
		req.Header.Set("If-Match", revision)
	}
	out := httptest.NewRecorder()
	router.ServeHTTP(out, req)
	return out
}

func runtimeResponse(t *testing.T, response *httptest.ResponseRecorder, status int) map[string]any {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("runtime response must not be cached")
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPolicyRuntimeReportsExactStartupBytesUntilExplicitApply(t *testing.T) {
	s, path := newRuntimePolicyTestServer(t, runtimePolicyFixture)
	restarts := 0
	s.restartService = func() { restarts++ }
	router := s.router()
	initialRevision := manifestETag([]byte(runtimePolicyFixture))
	candidate := strings.Replace(runtimePolicyFixture, "plan_high_first", "plan_low_first", 1)
	// Change disk after loadManifest but before the first observation.
	if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
		t.Fatal(err)
	}
	savedRevision := manifestETag([]byte(candidate))
	got := runtimeResponse(t, policyRuntimeRequest(router, http.MethodGet, "admin-secret", ""), 200)
	if got["activeRevision"] != initialRevision || got["persistedRevision"] != savedRevision || got["applySupported"] != true || got["blockedReason"] != nil {
		t.Fatalf("observation=%v", got)
	}
	selector := buildCoreAuthSelector(nil, &cockpitSelector{manifest: s.manifest}, s.manifest, nil)
	auths := []*coreauth.Auth{{ID: "a.json"}, {ID: "b.json"}, {ID: "c.json"}}
	pick := func(want string) {
		t.Helper()
		auth, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, auths)
		if err != nil || auth == nil || auth.ID != want {
			t.Fatalf("Pick=%v err=%v want=%s", auth, err, want)
		}
	}
	pick("a.json")
	for _, tc := range []struct {
		revision string
		status   int
	}{{"", 428}, {initialRevision, 412}} {
		runtimeResponse(t, policyRuntimeRequest(router, http.MethodPost, "admin-secret", tc.revision), tc.status)
		pick("a.json")
	}
	for i := 0; i < 2; i++ {
		got = runtimeResponse(t, policyRuntimeRequest(router, http.MethodPost, "admin-secret", savedRevision), 200)
		if got["activeRevision"] != savedRevision || got["persistedRevision"] != savedRevision || got["applySupported"] != true || got["blockedReason"] != nil {
			t.Fatalf("apply=%v", got)
		}
		pick("c.json")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != candidate {
		t.Fatalf("apply changed persisted bytes: %s, %v", data, err)
	}
	if restarts != 0 || s.manifest.RoutingStrategy != "plan_high_first" {
		t.Fatal("apply restarted or mutated the startup manifest")
	}
}

func TestPolicyRuntimeAdminAuthorizationAndUnavailable(t *testing.T) {
	fixture := strings.Replace(runtimePolicyFixture, `"apiKeys":[]`, `"apiKeys":[{"id":"client","key":"DO_NOT_EXPOSE","enabled":true,"accountIds":["a"]}]`, 1)
	s, path := newRuntimePolicyTestServer(t, fixture)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, token := range []string{"", "client-key", "wrong"} {
			response := policyRuntimeRequest(s.router(), method, token, manifestETag([]byte(fixture)))
			runtimeResponse(t, response, 401)
			for _, private := range []string{"DO_NOT_EXPOSE", "accounts", "routingStrategy"} {
				if strings.Contains(response.Body.String(), private) {
					t.Fatalf("unauthorized response exposes %s", private)
				}
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != fixture {
		t.Fatal("unauthorized request changed manifest")
	}
	got := runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 200)
	if got["activeRevision"] != manifestETag([]byte(fixture)) {
		t.Fatal("unauthorized request changed active revision")
	}
	s.adminToken = ""
	runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 503)
	s.adminToken = "admin-secret"
	s.manifest = &manifest{}
	got = runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 200)
	if got["activeRevision"] != nil || got["applySupported"] != false || got["blockedReason"] != "runtime_unavailable" {
		t.Fatalf("unavailable=%v", got)
	}
	runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(fixture))), 503)
}

func TestPolicyRuntimeBlocksEveryNonPolicyChange(t *testing.T) {
	for name, candidate := range map[string]string{
		"unknown-large-number": strings.Replace(runtimePolicyFixture, "9007199254740993", "9007199254740992", 1),
		"account":              strings.Replace(runtimePolicyFixture, `"planRank":3`, `"planRank":4`, 1),
		"new-field":            strings.Replace(runtimePolicyFixture, `"apiKeys":[]`, `"apiKeys":[],"newField":null`, 1),
		"removed-field":        strings.Replace(runtimePolicyFixture, `,"future":{"serial":9007199254740993}`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			s, path := newRuntimePolicyTestServer(t, runtimePolicyFixture)
			if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
				t.Fatal(err)
			}
			got := runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 200)
			if got["applySupported"] != false || got["blockedReason"] != "non_policy_change" {
				t.Fatalf("observation=%v", got)
			}
			runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(candidate))), 422)
			got = runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 200)
			if got["activeRevision"] != manifestETag([]byte(runtimePolicyFixture)) {
				t.Fatal("rejected apply changed active revision")
			}
		})
	}
}

func TestPolicyRuntimeRejectsUnsupportedPolicy(t *testing.T) {
	for name, replacement := range map[string]string{
		"unknown-strategy": `"routingStrategy":"future"`, "null-strategy": `"routingStrategy":null`,
		"null-rule": `"customRoutingRules":[null]`, "missing-account": `"customRoutingRules":[{}]`,
		"unknown-account": `"customRoutingRules":[{"accountId":"z"}]`,
		"duplicate":       `"customRoutingRules":[{"accountId":"a"},{"accountId":"a"}]`,
		"weight-zero":     `"customRoutingRules":[{"accountId":"a","weight":0}]`,
		"weight-high":     `"customRoutingRules":[{"accountId":"a","weight":10001}]`,
		"weight-null":     `"customRoutingRules":[{"accountId":"a","weight":null}]`,
		"weight-float":    `"customRoutingRules":[{"accountId":"a","weight":1.0}]`,
		"weight-bool":     `"customRoutingRules":[{"accountId":"a","weight":true}]`,
		"priority-high":   `"customRoutingRules":[{"accountId":"a","priority":10001}]`,
		"priority-low":    `"customRoutingRules":[{"accountId":"a","priority":-10001}]`,
		"role-null":       `"customRoutingRules":[{"accountId":"a","isBackup":null}]`,
		"roles-conflict":  `"customRoutingRules":[{"accountId":"a","isBackup":true,"isPreferred":true}]`,
	} {
		t.Run(name, func(t *testing.T) {
			s, path := newRuntimePolicyTestServer(t, runtimePolicyFixture)
			field := `"customRoutingRules":[]`
			if strings.Contains(name, "strategy") {
				field = `"routingStrategy":"plan_high_first"`
			}
			candidate := strings.Replace(runtimePolicyFixture, field, replacement, 1)
			if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
				t.Fatal(err)
			}
			got := runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 200)
			if got["blockedReason"] != "unsupported_policy" || got["applySupported"] != false {
				t.Fatalf("observation=%v", got)
			}
			runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(candidate))), 422)
		})
	}
}

type pausedPolicySelector struct {
	inner   coreauth.Selector
	entered chan struct{}
	resume  chan struct{}
}

func (s *pausedPolicySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*coreauth.Auth) (*coreauth.Auth, error) {
	close(s.entered)
	<-s.resume
	return s.inner.Pick(ctx, provider, model, opts, auths)
}

func TestPolicyRuntimeSnapshotSpansBackupAndOrdering(t *testing.T) {
	initial := strings.Replace(runtimePolicyFixture, `"customRoutingRules":[]`, `"customRoutingRules":[{"accountId":"a","isPreferred":true},{"accountId":"b","isPreferred":true}]`, 1)
	s, path := newRuntimePolicyTestServer(t, initial)
	gate := &pausedPolicySelector{inner: &cockpitSelector{manifest: s.manifest}, entered: make(chan struct{}), resume: make(chan struct{})}
	selector := &backupAccountSelector{manifest: s.manifest, fallback: gate}
	selected := make(chan string, 1)
	go func() {
		auth, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*coreauth.Auth{{ID: "a.json"}, {ID: "b.json"}, {ID: "c.json"}})
		if err != nil {
			selected <- err.Error()
			return
		}
		selected <- auth.ID
	}()
	<-gate.entered
	candidate := strings.Replace(strings.Replace(initial, "plan_high_first", "plan_low_first", 1), `"accountId":"b"`, `"accountId":"c"`, 1)
	if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
		t.Fatal(err)
	}
	response := policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(candidate)))
	close(gate.resume)
	runtimeResponse(t, response, 200)
	if got := <-selected; got != "a.json" {
		t.Fatalf("in-flight selection mixed policies: %s", got)
	}
}

func TestPolicyRuntimeConcurrentApplyAndSelection(t *testing.T) {
	s, path := newRuntimePolicyTestServer(t, runtimePolicyFixture)
	router := s.router()
	selector := buildCoreAuthSelector(nil, &cockpitSelector{manifest: s.manifest}, s.manifest, nil)
	auths := []*coreauth.Auth{{ID: "a.json"}, {ID: "b.json"}, {ID: "c.json"}}
	var workers sync.WaitGroup
	for i := 0; i < 3; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				auth, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, auths)
				if err != nil || auth == nil || (auth.ID != "a.json" && auth.ID != "c.json") {
					t.Errorf("selection=%v err=%v", auth, err)
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		strategy := "plan_high_first"
		if i%2 == 0 {
			strategy = "plan_low_first"
		}
		candidate := strings.Replace(runtimePolicyFixture, "plan_high_first", strategy, 1)
		if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
			t.Fatal(err)
		}
		runtimeResponse(t, policyRuntimeRequest(router, http.MethodPost, "admin-secret", manifestETag([]byte(candidate))), 200)
	}
	workers.Wait()
}

func TestPolicyRuntimeCompetingAdminSaveCannotFalselyActivateNewManifest(t *testing.T) {
	for i := 0; i < 20; i++ {
		s, path := newRuntimePolicyTestServer(t, runtimePolicyFixture)
		router := s.router()
		revision := manifestETag([]byte(runtimePolicyFixture))
		candidate := strings.Replace(runtimePolicyFixture, "9007199254740993", "9007199254740992", 1)
		start := make(chan struct{})
		saved := make(chan *httptest.ResponseRecorder, 1)
		applied := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			<-start
			saved <- adminManifestRequest(router, http.MethodPut, candidate, "admin-secret", revision)
		}()
		go func() { <-start; applied <- policyRuntimeRequest(router, http.MethodPost, "admin-secret", revision) }()
		close(start)
		writeResponse, applyResponse := <-saved, <-applied
		if writeResponse.Code != http.StatusAccepted {
			t.Fatalf("PUT=%d %s", writeResponse.Code, writeResponse.Body.String())
		}
		if applyResponse.Code != http.StatusOK && applyResponse.Code != http.StatusPreconditionFailed {
			t.Fatalf("apply=%d %s", applyResponse.Code, applyResponse.Body.String())
		}
		got := runtimeResponse(t, applyResponse, applyResponse.Code)
		if applyResponse.Code == http.StatusOK && (got["activeRevision"] != revision || got["persistedRevision"] != revision) {
			t.Fatalf("apply falsely activated winner: %v", got)
		}
		if applyResponse.Code == http.StatusPreconditionFailed && got["error"].(map[string]any)["code"] != "manifest_changed" {
			t.Fatalf("stale error=%v", got)
		}
		got = runtimeResponse(t, policyRuntimeRequest(router, http.MethodGet, "admin-secret", ""), 200)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got["activeRevision"] != revision || got["persistedRevision"] != manifestETag(data) || got["applySupported"] != false || got["blockedReason"] != "non_policy_change" {
			t.Fatalf("post-race state=%v", got)
		}
		if got["persistedRevision"] != writeResponse.Header().Get("ETag") {
			t.Fatal("PUT receipt does not match saved revision")
		}
		// After PUT completes, stale apply is always rejected without activating B.
		runtimeResponse(t, policyRuntimeRequest(router, http.MethodPost, "admin-secret", revision), 412)
	}
}

func TestPolicyRuntimeSupportedStrategiesDefaultsAndCustomWeights(t *testing.T) {
	for _, strategy := range []string{"auto", "random", "quota_high_first", "quota_low_first", "plan_high_first", "plan_low_first", "expiry_soon_first", "custom"} {
		t.Run(strategy, func(t *testing.T) {
			s, path := newRuntimePolicyTestServer(t, runtimePolicyFixture)
			candidate := strings.Replace(runtimePolicyFixture, "plan_high_first", strategy, 1)
			candidate = strings.Replace(candidate, `"customRoutingRules":[]`, `"customRoutingRules":[{"accountId":"a","weight":2,"unknownRuleField":{"keep":true}},{"accountId":"b"},{"accountId":"c","isBackup":true}]`, 1)
			if err := os.WriteFile(path, []byte(candidate), 0o600); err != nil {
				t.Fatal(err)
			}
			runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(candidate))), 200)
			selector := buildCoreAuthSelector(nil, &cockpitSelector{manifest: s.manifest}, s.manifest, nil)
			counts := map[string]int{}
			for i := 0; i < 6; i++ {
				auth, err := selector.Pick(context.Background(), "codex", "gpt-test", cliproxyexecutor.Options{}, []*coreauth.Auth{{ID: "a.json"}, {ID: "b.json"}, {ID: "c.json"}})
				if err != nil || auth == nil {
					t.Fatalf("Pick=%v %v", auth, err)
				}
				counts[auth.ID]++
			}
			if counts["c.json"] != 0 {
				t.Fatalf("backup chosen with regular accounts: %v", counts)
			}
			if strategy == "custom" && (counts["a.json"] != 4 || counts["b.json"] != 2) {
				t.Fatalf("weights 2/default1 not applied: %v", counts)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != candidate {
				t.Fatal("apply changed unknown rule data")
			}
		})
	}
}

func TestPolicyRuntimeAccountScopeAndBounds(t *testing.T) {
	accounts := make([]string, 257)
	for i := range accounts {
		accounts[i] = fmt.Sprintf(`{"id":"account-%d"}`, i)
	}
	for name, accountJSON := range map[string]string{
		"empty": `[]`, "null": `null`, "duplicate": `[{"id":"a"},{"id":"a"}]`,
		"invalid-id": `[{"id":"a/b"}]`, "long-id": `[{"id":"` + strings.Repeat("a", 257) + `"}]`,
		"too-many": "[" + strings.Join(accounts, ",") + "]", "unsupported-auth": `[{"id":"a","authKind":"api_key"}]`,
		"uppercase-auth": `[{"id":"a","authKind":"OAuth"}]`, "null-auth": `[{"id":"a","authKind":null}]`,
	} {
		t.Run(name, func(t *testing.T) {
			data := `{"accounts":` + accountJSON + `,"routingStrategy":"auto"}`
			s, _ := newRuntimePolicyTestServer(t, data)
			got := runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 200)
			if got["blockedReason"] != "unsupported_policy" || got["applySupported"] != false {
				t.Fatalf("scope=%v", got)
			}
			got = runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(data))), 422)
			if got["error"].(map[string]any)["code"] != "unsupported_policy" {
				t.Fatalf("error=%v", got)
			}
		})
	}
	// Inclusive account and rule limits, default strategy, and nullable empty rules.
	for _, data := range []string{
		`{"accounts":[{"id":"a"}],"customRoutingRules":null}`,
		`{"accounts":[{"id":"` + strings.Repeat("a", 256) + `"}]}`,
		`{"accounts":[` + strings.Join(accounts[:256], ",") + `],"customRoutingRules":[{"accountId":"account-0","priority":-10000,"weight":1},{"accountId":"account-255","priority":10000,"weight":10000}]}`,
	} {
		s, _ := newRuntimePolicyTestServer(t, data)
		runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(data))), 200)
	}
}

func TestPolicyRuntimeMalformedAndUnreadableManifestFailClosed(t *testing.T) {
	s, path := newRuntimePolicyTestServer(t, runtimePolicyFixture)
	for _, data := range []string{`null`, `[]`, `{"accounts":[]`, runtimePolicyFixture + ` {}`} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		got := runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodGet, "admin-secret", ""), 200)
		if got["applySupported"] != false || got["blockedReason"] != "unsupported_policy" || got["activeRevision"] != manifestETag([]byte(runtimePolicyFixture)) {
			t.Fatalf("malformed=%v", got)
		}
		runtimeResponse(t, policyRuntimeRequest(s.router(), http.MethodPost, "admin-secret", manifestETag([]byte(data))), 422)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		got := runtimeResponse(t, policyRuntimeRequest(s.router(), method, "admin-secret", manifestETag([]byte(runtimePolicyFixture))), 503)
		if got["error"].(map[string]any)["code"] != "runtime_unavailable" {
			t.Fatalf("error=%v", got)
		}
	}
}
