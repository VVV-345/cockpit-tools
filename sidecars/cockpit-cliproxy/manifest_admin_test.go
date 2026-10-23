package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

const adminManifestFixture = `{"apiKeys":[{"id":"key-1","key":"client-key","accountIds":["account-1"],"enabled":true}],"accounts":[{"id":"account-1","email":"one@example.com"}],"modelIds":["gpt-5.5"]}`

func newAdminManifestTestRouter(t *testing.T, token string) (*gin.Engine, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(adminManifestFixture), 0o600); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}
	gin.SetMode(gin.TestMode)
	return (&relayServer{
		policy:        &requestPolicy{},
		adminToken:    token,
		manifestAdmin: &manifestAdminStore{path: path},
	}).router(), path
}

func adminManifestRequest(router http.Handler, method, body, token, etag string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/admin/v1/manifest", strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestAdminManifestRequiresDedicatedToken(t *testing.T) {
	router, _ := newAdminManifestTestRouter(t, "admin-secret")

	for _, token := range []string{"", "client-key", "wrong-secret"} {
		response := adminManifestRequest(router, http.MethodGet, "", token, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("token %q status = %d, want %d", token, response.Code, http.StatusUnauthorized)
		}
	}
	response := adminManifestRequest(router, http.MethodGet, "", "admin-secret", "")
	if response.Code != http.StatusOK {
		t.Fatalf("valid admin token status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if response.Header().Get("ETag") == "" {
		t.Fatal("manifest response is missing ETag")
	}
}

func TestAdminManifestUpdatePersistsWithETagAndRequiresRestart(t *testing.T) {
	router, path := newAdminManifestTestRouter(t, "admin-secret")
	read := adminManifestRequest(router, http.MethodGet, "", "admin-secret", "")
	if read.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d; body=%s", read.Code, http.StatusOK, read.Body.String())
	}
	initialETag := read.Header().Get("ETag")
	if initialETag == "" {
		t.Fatal("GET response is missing ETag")
	}
	updated := `{"apiKeys":[],"accounts":[{"id":"account-2","email":"two@example.com"}],"modelIds":["gpt-5.6"]}`

	missingPrecondition := adminManifestRequest(router, http.MethodPut, updated, "admin-secret", "")
	if missingPrecondition.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match status = %d, want %d", missingPrecondition.Code, http.StatusPreconditionRequired)
	}
	stalePrecondition := adminManifestRequest(router, http.MethodPut, updated, "admin-secret", `"stale"`)
	if stalePrecondition.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match status = %d, want %d", stalePrecondition.Code, http.StatusPreconditionFailed)
	}

	response := adminManifestRequest(router, http.MethodPut, updated, "admin-secret", initialETag)
	if response.Code != http.StatusAccepted {
		t.Fatalf("PUT status = %d, want %d; body=%s", response.Code, http.StatusAccepted, response.Body.String())
	}
	var result struct {
		RestartRequired bool `json:"restartRequired"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if !result.RestartRequired {
		t.Fatal("PUT response must state that restart is required")
	}
	if response.Header().Get("ETag") == "" || response.Header().Get("ETag") == initialETag {
		t.Fatalf("updated response ETag = %q, initial %q", response.Header().Get("ETag"), initialETag)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted manifest: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(persisted, &got); err != nil {
		t.Fatalf("persisted manifest is invalid JSON: %v", err)
	}
	accounts, ok := got["accounts"].([]any)
	if !ok || len(accounts) != 1 || accounts[0].(map[string]any)["id"] != "account-2" {
		t.Fatalf("persisted accounts = %#v", got["accounts"])
	}
}

func TestAdminManifestRejectsInvalidUpdateWithoutChangingFile(t *testing.T) {
	router, path := newAdminManifestTestRouter(t, "admin-secret")
	read := adminManifestRequest(router, http.MethodGet, "", "admin-secret", "")
	if read.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", read.Code, http.StatusOK)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read original manifest: %v", err)
	}
	invalid := `{"apiKeys":[{"id":"duplicate","key":"one","enabled":true},{"id":"duplicate","key":"two","enabled":true}],"accounts":[],"modelIds":[]}`
	response := adminManifestRequest(router, http.MethodPut, invalid, "admin-secret", read.Header().Get("ETag"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid manifest status = %d, want %d; body=%s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest after invalid update: %v", err)
	}
	if string(after) != string(original) {
		t.Fatal("invalid update changed the persisted manifest")
	}
}

func TestAdminManifestRejectsEnabledPoolKeyWithoutValidAccountScope(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		accounts string
	}{
		{
			name:     "missing scope",
			apiKey:   `{"id":"key-1","key":"client-key","enabled":true}`,
			accounts: `[{"id":"account-1"}]`,
		},
		{
			name:     "empty scope",
			apiKey:   `{"id":"key-1","key":"client-key","accountIds":[],"enabled":true}`,
			accounts: `[{"id":"account-1"}]`,
		},
		{
			name:     "unknown account",
			apiKey:   `{"id":"key-1","key":"client-key","accountIds":["missing-account"],"enabled":true}`,
			accounts: `[{"id":"account-1"}]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(`{"apiKeys":[` + test.apiKey + `],"accounts":` + test.accounts + `}`)
			if err := validateAdminManifest(data); !errors.Is(err, errInvalidManifest) && err == nil {
				t.Fatal("expected invalid manifest error")
			}
		})
	}
}

func TestAdminManifestAllowsProviderGatewayKeyWithoutAccountScope(t *testing.T) {
	data := []byte(`{"apiKeys":[{"id":"key-1","key":"client-key","providerGateway":{"baseUrl":"https://provider.example/v1","apiKey":"provider-key","upstreamModel":"model-1"},"enabled":true}],"accounts":[]}`)
	if err := validateAdminManifest(data); err != nil {
		t.Fatalf("valid provider gateway manifest rejected: %v", err)
	}
}

func newAdminAuthFileTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "auth")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create auth directory: %v", err)
	}
	gin.SetMode(gin.TestMode)
	return (&relayServer{
		policy:        &requestPolicy{},
		adminToken:    "admin-secret",
		manifestAdmin: &manifestAdminStore{path: filepath.Join(root, "manifest.json"), authDir: path},
	}).router(), path
}

func adminAuthFileRequest(router http.Handler, method, name, body, token, ifMatch, ifNoneMatch string) *httptest.ResponseRecorder {
	path := "/admin/v1/auth-files"
	if name != "" {
		path += "/" + name
	}
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if ifNoneMatch != "" {
		request.Header.Set("If-None-Match", ifNoneMatch)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestAdminAuthFilesUseConditionalWritesAndListOnlyMetadata(t *testing.T) {
	router, authDir := newAdminAuthFileTestRouter(t)
	body := `{"type":"codex","access_token":"secret-token"}`
	created := adminAuthFileRequest(router, http.MethodPut, "account-1.json", body, "admin-secret", "", "*")
	if created.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d; body=%s", created.Code, http.StatusAccepted, created.Body.String())
	}
	var createResponse struct {
		RestartRequired bool `json:"restartRequired"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createResponse); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !createResponse.RestartRequired {
		t.Fatal("create response must require restart")
	}
	createdETag := created.Header().Get("ETag")
	if createdETag == "" {
		t.Fatal("create response is missing ETag")
	}

	listed := adminAuthFileRequest(router, http.MethodGet, "", "", "admin-secret", "", "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d; body=%s", listed.Code, http.StatusOK, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), "secret-token") {
		t.Fatal("auth-file listing exposed credential contents")
	}
	var listing struct {
		Files []struct {
			ID   string `json:"id"`
			ETag string `json:"etag"`
			Size int64  `json:"size"`
		} `json:"files"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &listing); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	if len(listing.Files) != 1 || listing.Files[0].ID != "account-1.json" || listing.Files[0].ETag != createdETag || listing.Files[0].Size != int64(len(body)) {
		t.Fatalf("listing = %#v", listing.Files)
	}

	path := filepath.Join(authDir, "account-1.json")
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted auth file: %v", err)
	}
	if string(persisted) != body {
		t.Fatal("persisted auth file does not match request body")
	}

	stale := adminAuthFileRequest(router, http.MethodPut, "account-1.json", body, "admin-secret", `"stale"`, "")
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale update status = %d, want %d; body=%s", stale.Code, http.StatusPreconditionFailed, stale.Body.String())
	}
}

func TestAdminAuthFilesUpdateAndDeleteWithCurrentETag(t *testing.T) {
	router, authDir := newAdminAuthFileTestRouter(t)
	created := adminAuthFileRequest(router, http.MethodPut, "account-1.json", `{"type":"codex","access_token":"first"}`, "admin-secret", "", "*")
	if created.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d; body=%s", created.Code, http.StatusAccepted, created.Body.String())
	}

	updated := adminAuthFileRequest(router, http.MethodPut, "account-1.json", `{"type":"codex","access_token":"second"}`, "admin-secret", created.Header().Get("ETag"), "")
	if updated.Code != http.StatusAccepted {
		t.Fatalf("update status = %d, want %d; body=%s", updated.Code, http.StatusAccepted, updated.Body.String())
	}
	if updated.Header().Get("ETag") == created.Header().Get("ETag") {
		t.Fatal("updated auth file must have a new ETag")
	}

	staleDelete := adminAuthFileRequest(router, http.MethodDelete, "account-1.json", "", "admin-secret", created.Header().Get("ETag"), "")
	if staleDelete.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale delete status = %d, want %d; body=%s", staleDelete.Code, http.StatusPreconditionFailed, staleDelete.Body.String())
	}
	deleted := adminAuthFileRequest(router, http.MethodDelete, "account-1.json", "", "admin-secret", updated.Header().Get("ETag"), "")
	if deleted.Code != http.StatusAccepted {
		t.Fatalf("delete status = %d, want %d; body=%s", deleted.Code, http.StatusAccepted, deleted.Body.String())
	}
	if _, err := os.Stat(filepath.Join(authDir, "account-1.json")); !os.IsNotExist(err) {
		t.Fatalf("auth file stat error = %v, want not-exist", err)
	}
}

func TestAdminAuthFilesRejectMissingPreconditionsInvalidJSONAndUnsafeNames(t *testing.T) {
	router, authDir := newAdminAuthFileTestRouter(t)
	missingPrecondition := adminAuthFileRequest(router, http.MethodPut, "account-1.json", `{"type":"codex"}`, "admin-secret", "", "")
	if missingPrecondition.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing precondition status = %d, want %d; body=%s", missingPrecondition.Code, http.StatusPreconditionRequired, missingPrecondition.Body.String())
	}
	invalidJSON := adminAuthFileRequest(router, http.MethodPut, "account-1.json", `{"access_token":"secret"}`, "admin-secret", "", "*")
	if invalidJSON.Code != http.StatusBadRequest {
		t.Fatalf("invalid auth status = %d, want %d; body=%s", invalidJSON.Code, http.StatusBadRequest, invalidJSON.Body.String())
	}
	unsafeName := adminAuthFileRequest(router, http.MethodPut, "..hidden.json", `{"type":"codex"}`, "admin-secret", "", "*")
	if unsafeName.Code != http.StatusBadRequest {
		t.Fatalf("unsafe name status = %d, want %d; body=%s", unsafeName.Code, http.StatusBadRequest, unsafeName.Body.String())
	}
	if _, err := os.Stat(filepath.Join(authDir, "account-1.json")); !os.IsNotExist(err) {
		t.Fatalf("invalid auth write left a file, stat error = %v", err)
	}
}

func TestAdminManifestIsDisabledWithoutConfiguredToken(t *testing.T) {
	router, _ := newAdminManifestTestRouter(t, "")
	response := adminManifestRequest(router, http.MethodGet, "", "anything", "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
}

func TestAdminManifestConcurrentUpdatesRejectStaleETag(t *testing.T) {
	_, path := newAdminManifestTestRouter(t, "admin-secret")
	store := &manifestAdminStore{path: path}
	_, etag, err := store.read()
	if err != nil {
		t.Fatalf("read initial manifest: %v", err)
	}
	bodies := [][]byte{
		[]byte(`{"apiKeys":[],"accounts":[{"id":"account-a"}],"modelIds":[]}`),
		[]byte(`{"apiKeys":[],"accounts":[{"id":"account-b"}],"modelIds":[]}`),
	}
	start := make(chan struct{})
	results := make(chan error, len(bodies))
	var wait sync.WaitGroup
	for _, body := range bodies {
		wait.Add(1)
		go func(body []byte) {
			defer wait.Done()
			<-start
			_, writeErr := store.write(etag, body)
			results <- writeErr
		}(body)
	}
	close(start)
	wait.Wait()
	close(results)

	succeeded := 0
	conflicted := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errManifestPreconditionFailed):
			conflicted++
		default:
			t.Fatalf("unexpected update error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent updates: succeeded=%d conflicted=%d, want 1 each", succeeded, conflicted)
	}
}

func TestAdminRestartRequiresDedicatedTokenAndSupervisor(t *testing.T) {
	router, _ := newAdminManifestTestRouter(t, "admin-secret")

	unauthorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/restart", nil)
	router.ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized restart status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	unsupervised := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/admin/v1/restart", nil)
	request.Header.Set("Authorization", "Bearer admin-secret")
	router.ServeHTTP(unsupervised, request)
	if unsupervised.Code != http.StatusServiceUnavailable {
		t.Fatalf("unsupervised restart status = %d, want %d; body=%s", unsupervised.Code, http.StatusServiceUnavailable, unsupervised.Body.String())
	}
}

func TestAdminRestartSchedulesSupervisedShutdown(t *testing.T) {
	var calls int
	gin.SetMode(gin.TestMode)
	router := (&relayServer{
		policy:         &requestPolicy{},
		adminToken:     "admin-secret",
		restartService: func() { calls++ },
	}).router()

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/restart", nil)
	request.Header.Set("Authorization", "Bearer admin-secret")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("restart status = %d, want %d; body=%s", response.Code, http.StatusAccepted, response.Body.String())
	}
	if calls != 1 {
		t.Fatalf("restart callback calls = %d, want 1", calls)
	}
}
