package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

const maxAdminManifestBytes int64 = 1 << 20
const maxAdminAuthFileBytes int64 = 4 << 20

var (
	errManifestPreconditionRequired = errors.New("manifest update requires If-Match")
	errManifestPreconditionFailed   = errors.New("manifest changed since it was read")
	errInvalidManifest              = errors.New("invalid manifest")
	errAuthFilePreconditionRequired = errors.New("auth file update requires a matching precondition")
	errAuthFilePreconditionFailed   = errors.New("auth file changed since it was read")
	errAuthFileNotFound             = errors.New("auth file not found")
	errInvalidAuthFile              = errors.New("invalid auth file")
	errInvalidAuthFileName          = errors.New("invalid auth file name")
)

type manifestAdminStore struct {
	path    string
	authDir string
	mu      sync.Mutex
}

type adminAuthFileInfo struct {
	ID   string `json:"id"`
	ETag string `json:"etag"`
	Size int64  `json:"size"`
}

func (s *manifestAdminStore) read() ([]byte, string, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil, "", errors.New("manifest store unavailable")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, "", err
	}
	return data, manifestETag(data), nil
}

func (s *manifestAdminStore) write(expectedETag string, data []byte) (string, error) {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return "", errors.New("manifest store unavailable")
	}
	if strings.TrimSpace(expectedETag) == "" {
		return "", errManifestPreconditionRequired
	}
	if err := validateAdminManifest(data); err != nil {
		return "", fmt.Errorf("%w: %v", errInvalidManifest, err)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, data, "", "  "); err != nil {
		return "", fmt.Errorf("%w: %v", errInvalidManifest, err)
	}
	formatted.WriteByte('\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := os.ReadFile(s.path)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(expectedETag) != manifestETag(current) {
		return "", errManifestPreconditionFailed
	}
	if err := writeManifestAtomically(s.path, formatted.Bytes()); err != nil {
		return "", err
	}
	return manifestETag(formatted.Bytes()), nil
}

func (s *manifestAdminStore) listAuthFiles() ([]adminAuthFileInfo, error) {
	if s == nil || strings.TrimSpace(s.authDir) == "" {
		return nil, errors.New("auth file store unavailable")
	}
	entries, err := os.ReadDir(s.authDir)
	if err != nil {
		return nil, err
	}
	files := make([]adminAuthFileInfo, 0, len(entries))
	for _, entry := range entries {
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.authDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, adminAuthFileInfo{ID: entry.Name(), ETag: manifestETag(data), Size: info.Size()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ID < files[j].ID })
	return files, nil
}

func (s *manifestAdminStore) writeAuthFile(name, expectedETag, ifNoneMatch string, data []byte) (string, error) {
	if s == nil || strings.TrimSpace(s.authDir) == "" {
		return "", errors.New("auth file store unavailable")
	}
	path, err := adminAuthFilePath(s.authDir, name)
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxAdminAuthFileBytes {
		return "", fmt.Errorf("%w: auth file exceeds the 4 MiB limit", errInvalidAuthFile)
	}
	if err := validateAdminAuthFile(data); err != nil {
		return "", fmt.Errorf("%w: %v", errInvalidAuthFile, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.authDir, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		if strings.TrimSpace(expectedETag) != "" {
			return "", errAuthFilePreconditionFailed
		}
		if strings.TrimSpace(ifNoneMatch) != "*" {
			return "", errAuthFilePreconditionRequired
		}
	case err != nil:
		return "", err
	default:
		if !info.Mode().IsRegular() {
			return "", errInvalidAuthFileName
		}
		if strings.TrimSpace(ifNoneMatch) != "" {
			return "", errAuthFilePreconditionFailed
		}
		if strings.TrimSpace(expectedETag) == "" {
			return "", errAuthFilePreconditionRequired
		}
		current, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(expectedETag) != manifestETag(current) {
			return "", errAuthFilePreconditionFailed
		}
	}
	if strings.TrimSpace(ifNoneMatch) != "" && strings.TrimSpace(ifNoneMatch) != "*" {
		return "", errAuthFilePreconditionRequired
	}
	if err := writeManifestAtomically(path, data); err != nil {
		return "", err
	}
	return manifestETag(data), nil
}

func (s *manifestAdminStore) deleteAuthFile(name, expectedETag string) error {
	if s == nil || strings.TrimSpace(s.authDir) == "" {
		return errors.New("auth file store unavailable")
	}
	path, err := adminAuthFilePath(s.authDir, name)
	if err != nil {
		return err
	}
	if strings.TrimSpace(expectedETag) == "" {
		return errAuthFilePreconditionRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return errAuthFileNotFound
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errInvalidAuthFileName
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(expectedETag) != manifestETag(data) {
		return errAuthFilePreconditionFailed
	}
	return os.Remove(path)
}

func adminAuthFilePath(authDir, name string) (string, error) {
	if strings.TrimSpace(name) != name || name == "" || name[0] == '.' ||
		strings.ContainsAny(name, `/\:*?"<>|`) || strings.ContainsAny(name, "\x00\r\n") ||
		filepath.Base(name) != name || !strings.EqualFold(filepath.Ext(name), ".json") {
		return "", errInvalidAuthFileName
	}
	return filepath.Join(authDir, name), nil
}

func validateAdminAuthFile(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("auth file must be a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("auth file must be valid JSON")
	}
	var provider string
	if err := json.Unmarshal(fields["type"], &provider); err != nil || strings.TrimSpace(provider) == "" {
		return errors.New("auth file must include a non-empty type")
	}
	return nil
}

func validateAdminManifest(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return errors.New("manifest must be a JSON object")
	}
	var candidate manifest
	if err := json.Unmarshal(data, &candidate); err != nil {
		return errors.New("manifest must be valid JSON")
	}
	accountIDs := make(map[string]struct{}, len(candidate.Accounts))
	for _, account := range candidate.Accounts {
		id := strings.TrimSpace(account.ID)
		if id == "" {
			return errors.New("every account must have an id")
		}
		if _, exists := accountIDs[id]; exists {
			return fmt.Errorf("duplicate account id %q", id)
		}
		accountIDs[id] = struct{}{}
	}
	apiKeyIDs := make(map[string]struct{}, len(candidate.APIKeys))
	apiKeyValues := make(map[string]struct{}, len(candidate.APIKeys))
	for _, apiKey := range candidate.APIKeys {
		id := strings.TrimSpace(apiKey.ID)
		if id == "" {
			return errors.New("every API key must have an id")
		}
		if _, exists := apiKeyIDs[id]; exists {
			return fmt.Errorf("duplicate API key id %q", id)
		}
		apiKeyIDs[id] = struct{}{}
		value := strings.TrimSpace(apiKey.Key)
		if apiKey.Enabled && value == "" {
			return fmt.Errorf("enabled API key %q must have a key value", id)
		}
		if apiKey.Enabled {
			if _, exists := apiKeyValues[value]; exists {
				return errors.New("duplicate enabled API key value")
			}
			apiKeyValues[value] = struct{}{}
			if apiKey.ProviderGateway != nil {
				gateway := *apiKey.ProviderGateway
				if !normalizeProviderGatewaySpec(&gateway) {
					return fmt.Errorf("API key %q has an invalid provider gateway", id)
				}
				continue
			}
			if len(apiKey.AccountIDs) == 0 {
				return fmt.Errorf("enabled API key %q must have at least one account", id)
			}
			for _, accountID := range apiKey.AccountIDs {
				accountID = strings.TrimSpace(accountID)
				if accountID == "" {
					return fmt.Errorf("enabled API key %q has an empty account id", id)
				}
				if _, exists := accountIDs[accountID]; !exists {
					return fmt.Errorf("enabled API key %q references unknown account %q", id, accountID)
				}
			}
		}
	}
	return nil
}

func writeManifestAtomically(path string, data []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".manifest-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func manifestETag(data []byte) string {
	digest := sha256.Sum256(data)
	return `"sha256-` + hex.EncodeToString(digest[:]) + `"`
}

func (s *relayServer) requireAdminToken(c *gin.Context) bool {
	expected := strings.TrimSpace(s.adminToken)
	if expected == "" {
		writeAPIError(c, http.StatusServiceUnavailable, "admin API is disabled", "admin_api_disabled")
		return false
	}
	parts := strings.Fields(c.GetHeader("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		writeAPIError(c, http.StatusUnauthorized, "missing or invalid admin token", "invalid_admin_token")
		return false
	}
	gotHash := sha256.Sum256([]byte(parts[1]))
	expectedHash := sha256.Sum256([]byte(expected))
	if subtle.ConstantTimeCompare(gotHash[:], expectedHash[:]) != 1 {
		writeAPIError(c, http.StatusUnauthorized, "missing or invalid admin token", "invalid_admin_token")
		return false
	}
	return true
}

func (s *relayServer) handleGetAdminManifest(c *gin.Context) {
	if !s.requireAdminToken(c) {
		return
	}
	data, etag, err := s.manifestAdmin.read()
	if err != nil {
		writeAPIError(c, http.StatusServiceUnavailable, "manifest store unavailable", "manifest_store_unavailable")
		return
	}
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/json", data)
}

func (s *relayServer) handleAdminRestart(c *gin.Context) {
	if !s.requireAdminToken(c) {
		return
	}
	if s.restartService == nil {
		writeAPIError(c, http.StatusServiceUnavailable, "service restart is unavailable", "restart_unavailable")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusAccepted, gin.H{"status": "restart_scheduled"})
	s.restartOnce.Do(s.restartService)
}

func (s *relayServer) handleListAdminAuthFiles(c *gin.Context) {
	if !s.requireAdminToken(c) {
		return
	}
	files, err := s.manifestAdmin.listAuthFiles()
	if err != nil {
		writeAPIError(c, http.StatusServiceUnavailable, "auth file store unavailable", "auth_file_store_unavailable")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func (s *relayServer) handlePutAdminAuthFile(c *gin.Context) {
	if !s.requireAdminToken(c) {
		return
	}
	if s.manifestAdmin == nil {
		writeAPIError(c, http.StatusServiceUnavailable, "auth file store unavailable", "auth_file_store_unavailable")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxAdminAuthFileBytes))
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeAPIError(c, http.StatusRequestEntityTooLarge, "auth file exceeds the 4 MiB limit", "auth_file_too_large")
			return
		}
		writeAPIError(c, http.StatusBadRequest, "failed to read auth file", "invalid_auth_file")
		return
	}
	etag, err := s.manifestAdmin.writeAuthFile(c.Param("name"), c.GetHeader("If-Match"), c.GetHeader("If-None-Match"), data)
	switch {
	case errors.Is(err, errAuthFilePreconditionRequired):
		writeAPIError(c, http.StatusPreconditionRequired, err.Error(), "auth_file_precondition_required")
		return
	case errors.Is(err, errAuthFilePreconditionFailed):
		writeAPIError(c, http.StatusPreconditionFailed, err.Error(), "auth_file_changed")
		return
	case errors.Is(err, errInvalidAuthFile), errors.Is(err, errInvalidAuthFileName):
		writeAPIError(c, http.StatusBadRequest, err.Error(), "invalid_auth_file")
		return
	case err != nil:
		writeAPIError(c, http.StatusInternalServerError, "failed to persist auth file", "auth_file_write_failed")
		return
	}
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusAccepted, gin.H{"status": "persisted", "restartRequired": true})
}

func (s *relayServer) handleDeleteAdminAuthFile(c *gin.Context) {
	if !s.requireAdminToken(c) {
		return
	}
	if s.manifestAdmin == nil {
		writeAPIError(c, http.StatusServiceUnavailable, "auth file store unavailable", "auth_file_store_unavailable")
		return
	}
	if err := s.manifestAdmin.deleteAuthFile(c.Param("name"), c.GetHeader("If-Match")); err != nil {
		switch {
		case errors.Is(err, errAuthFilePreconditionRequired):
			writeAPIError(c, http.StatusPreconditionRequired, err.Error(), "auth_file_precondition_required")
		case errors.Is(err, errAuthFilePreconditionFailed):
			writeAPIError(c, http.StatusPreconditionFailed, err.Error(), "auth_file_changed")
		case errors.Is(err, errAuthFileNotFound):
			writeAPIError(c, http.StatusNotFound, err.Error(), "auth_file_not_found")
		case errors.Is(err, errInvalidAuthFileName):
			writeAPIError(c, http.StatusBadRequest, err.Error(), "invalid_auth_file")
		default:
			writeAPIError(c, http.StatusInternalServerError, "failed to delete auth file", "auth_file_delete_failed")
		}
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusAccepted, gin.H{"status": "deleted", "restartRequired": true})
}

func (s *relayServer) handlePutAdminManifest(c *gin.Context) {
	if !s.requireAdminToken(c) {
		return
	}
	if s.manifestAdmin == nil {
		writeAPIError(c, http.StatusServiceUnavailable, "manifest store unavailable", "manifest_store_unavailable")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxAdminManifestBytes))
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeAPIError(c, http.StatusRequestEntityTooLarge, "manifest exceeds the 1 MiB limit", "manifest_too_large")
			return
		}
		writeAPIError(c, http.StatusBadRequest, "failed to read manifest", "invalid_request")
		return
	}
	etag, err := s.manifestAdmin.write(c.GetHeader("If-Match"), data)
	switch {
	case errors.Is(err, errManifestPreconditionRequired):
		writeAPIError(c, http.StatusPreconditionRequired, err.Error(), "if_match_required")
		return
	case errors.Is(err, errManifestPreconditionFailed):
		writeAPIError(c, http.StatusPreconditionFailed, err.Error(), "manifest_changed")
		return
	case errors.Is(err, errInvalidManifest):
		writeAPIError(c, http.StatusBadRequest, err.Error(), "invalid_manifest")
		return
	case err != nil:
		writeAPIError(c, http.StatusInternalServerError, "failed to persist manifest", "manifest_write_failed")
		return
	}
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusAccepted, gin.H{
		"status":          "persisted",
		"restartRequired": true,
	})
}
