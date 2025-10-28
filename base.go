package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Token storage for base mode
type baseSession struct {
	ServiceToken string    `json:"service_token"`
	MaasAPIBase  string    `json:"maas_api_base"`
	ExpiresAt    time.Time `json:"expires_at"`
	ObtainedAt   time.Time `json:"obtained_at"`
}

func baseSessionFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".maas-cli", "base-session.json"), nil
}

func loadBaseSession() (*baseSession, error) {
	path, err := baseSessionFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var session baseSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func saveBaseSession(session *baseSession) error {
	if session == nil {
		return errors.New("nil session")
	}
	path, err := baseSessionFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (s *baseSession) expired() bool {
	if s == nil {
		return true
	}
	if s.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(s.ExpiresAt.Add(-1 * time.Minute))
}

// Get OpenShift token using 'oc whoami -t' (for creating service account tokens)
func getOpenShiftTokenBase() (string, error) {
	cmd := exec.Command("oc", "whoami", "-t")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("oc command failed (make sure you're logged into OpenShift): %w", err)
	}

	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", errors.New("empty token returned from 'oc whoami -t'")
	}

	return token, nil
}

// Get OpenShift cluster domain using kubectl
func getClusterDomainBase() (string, error) {
	cmd := exec.Command("kubectl", "get", "ingresses.config.openshift.io", "cluster", "-o", "jsonpath={.spec.domain}")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("kubectl command failed: %w", err)
	}

	domain := strings.TrimSpace(string(output))
	if domain == "" {
		return "", errors.New("empty domain returned from kubectl")
	}

	return domain, nil
}

// Get MaaS API base URL by auto-detecting from cluster domain
func getMaasAPIBaseBase() (string, error) {
	domain, err := getClusterDomainBase()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("https://maas.%s", domain), nil
}

// Ensure we have a valid service account token for API calls
func ensureBaseToken() (string, string, error) {
	session, err := loadBaseSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to load session: %w", err)
	}

	// Check if we have a valid stored token
	if session != nil && !session.expired() && session.ServiceToken != "" && session.MaasAPIBase != "" {
		return session.ServiceToken, session.MaasAPIBase, nil
	}

	// Need to create a new token
	fmt.Println("No valid service token found. Please run /get-token first.")
	return "", "", errors.New("no valid service token available")
}

// Helper function to get first available model
func getFirstAvailableModel(serviceToken, apiBase string) (string, string, error) {
	// Get models from API
	modelsReq, _ := http.NewRequest(http.MethodGet, apiBase+"/maas-api/v1/models", nil)
	modelsReq.Header.Set("Authorization", "Bearer "+serviceToken)
	modelsReq.Header.Set("Content-Type", "application/json")

	client := newAPIClient(true)
	resp, err := client.Do(modelsReq)
	if err != nil {
		return "", "", fmt.Errorf("failed to get models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("models request failed: %s", resp.Status)
	}

	var payload struct {
		Data []struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", fmt.Errorf("failed to decode models response: %w", err)
	}

	if len(payload.Data) == 0 {
		return "", "", fmt.Errorf("no models available")
	}

	// Use first available model
	modelName := payload.Data[0].ID
	// Use the URL from API response and append /v1/chat/completions
	modelURL := strings.Replace(payload.Data[0].URL, "http://", "https://", 1)
	modelURL = modelURL + "/v1/chat/completions"

	return modelName, modelURL, nil
}

// Base mode command handlers

func handleGetEndpointBase(ctx *commandContext) {
	domain, err := getClusterDomainBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get cluster domain: %v\n", err)
		return
	}

	endpoint := fmt.Sprintf("maas.%s", domain)

	if ctx.showCurl {
		fmt.Printf("kubectl get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'\n")
		return
	}

	fmt.Printf("Gateway endpoint: %s\n", endpoint)
	fmt.Printf("Full MaaS API URL: https://%s\n", endpoint)
}

func handleGetTokenBase(ctx *commandContext) {
	// Parse expiration from args
	args := strings.Fields(ctx.args)
	expiration := "8h" // default to 8 hours as requested
	if len(args) > 0 {
		expiration = args[0]
	}

	// Get OpenShift token for authentication
	osToken, err := getOpenShiftTokenBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get OpenShift token: %v\n", err)
		return
	}

	// Get MaaS API base URL
	apiBase, err := getMaasAPIBaseBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get MaaS API base URL: %v\n", err)
		return
	}

	// Prepare token creation request
	payload := map[string]interface{}{
		"expiration": expiration,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode request: %v\n", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/maas-api/v1/tokens", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to build request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+osToken)
	req.Header.Set("Content-Type", "application/json")

	if ctx.showCurl {
		printCurlCommand(req)
		return
	}

	client := newAPIClient(true) // insecure for now
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fmt.Fprintf(os.Stderr, "Error: token creation failed (%s): %s\n", resp.Status, strings.TrimSpace(string(body)))
		return
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to decode response: %v\n", err)
		return
	}

	// Parse expiration duration to calculate expires_at
	duration, err := time.ParseDuration(expiration)
	if err != nil {
		// Default to 8 hours if parsing fails
		duration = 8 * time.Hour
	}

	// Store the token for future use
	session := &baseSession{
		ServiceToken: tokenResp.Token,
		MaasAPIBase:  apiBase,
		ExpiresAt:    time.Now().Add(duration),
		ObtainedAt:   time.Now(),
	}

	if err := saveBaseSession(session); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save token: %v\n", err)
	}

	fmt.Printf("✓ Service account token created (expires in %s)\n", expiration)
	fmt.Printf("Token: %s\n", tokenResp.Token)
	fmt.Println("Token stored for subsequent CLI commands")
}

func handleModelsBase(ctx *commandContext) {
	// Get stored service account token
	serviceToken, apiBase, err := ensureBaseToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Build request to new models endpoint
	endpoint := apiBase + "/maas-api/v1/models"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to build request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+serviceToken)
	req.Header.Set("Content-Type", "application/json")

	if ctx.showCurl {
		printCurlCommand(req)
		return
	}

	client := newAPIClient(true) // insecure for now
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fmt.Fprintf(os.Stderr, "Error: models request failed (%s): %s\n", resp.Status, strings.TrimSpace(string(body)))
		return
	}

	var payload struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to decode response: %v\n", err)
		return
	}

	if len(payload.Data) == 0 {
		fmt.Println("No models are currently available.")
		return
	}

	fmt.Printf("Available models (%d)\n\n", len(payload.Data))
	for _, model := range payload.Data {
		fmt.Printf("  • %s\n", model.ID)
		if model.Name != "" && model.Name != model.ID {
			fmt.Printf("      Name: %s\n", model.Name)
		}
		fmt.Println()
	}
}

func handleTestModelBase(ctx *commandContext) {
	// Parse arguments: model-name and prompt
	args := strings.Fields(ctx.args)
	var modelName, prompt string

	if len(args) > 0 {
		modelName = args[0]
	}
	if len(args) > 1 {
		prompt = strings.Join(args[1:], " ")
	}

	if prompt == "" {
		prompt = "Hello" // default from validation script
	}

	// Get stored service account token
	serviceToken, apiBase, err := ensureBaseToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// If no model specified, get the first available model
	var modelURL string
	if modelName == "" {
		var err error
		modelName, modelURL, err = getFirstAvailableModel(serviceToken, apiBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
	} else {
		// For provided model name, we still need to get the correct URL from the API
		// This ensures we use the right endpoint even for custom model names
		_, modelURL, err = getFirstAvailableModel(serviceToken, apiBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		// For custom model names, we need to construct the URL based on the API pattern
		// Replace the model part after /llm/ with the custom model name
		baseURL := strings.Split(modelURL, "/llm/")[0]
		// Convert model ID to URL format (facebook/opt-125m -> facebook-opt-125m-simulated)
		modelURLPart := strings.ReplaceAll(modelName, "/", "-") + "-simulated"
		modelURL = baseURL + "/llm/" + modelURLPart + "/v1/chat/completions"
	}
	payload := map[string]interface{}{
		"model":      modelName,
		"prompt":     prompt,
		"max_tokens": 50,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode request: %v\n", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, modelURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to build request: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+serviceToken)
	req.Header.Set("Content-Type", "application/json")

	if ctx.showCurl {
		printCurlCommand(req)
		return
	}

	client := newAPIClient(true)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("✓ Model test completed\n")
	fmt.Printf("Model: %s\n", modelName)
	fmt.Printf("Prompt: %s\n", prompt)
	fmt.Printf("Status: %s\n", resp.Status)

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fmt.Printf("Response: %s\n", strings.TrimSpace(string(body)))
	} else {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if respJSON, err := json.MarshalIndent(result, "", "  "); err == nil {
				fmt.Printf("Response:\n%s\n", string(respJSON))
			}
		}
	}
}

func handleTestAuthBase(ctx *commandContext) {
	// Parse model name argument
	args := strings.Fields(ctx.args)
	var modelName string
	if len(args) > 0 {
		modelName = args[0]
	}

	// Get MaaS API base URL and need a token to get model info
	apiBase, err := getMaasAPIBaseBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get MaaS API base URL: %v\n", err)
		return
	}

	// Get a temporary token to fetch model info, then test without auth
	tempToken, err := getOpenShiftTokenBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to get OpenShift token for model lookup: %v\n", err)
		return
	}

	// If no model specified, get the first available model
	var modelURL string
	if modelName == "" {
		modelName, modelURL, err = getFirstAvailableModel(tempToken, apiBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
	} else {
		// For provided model name, construct URL using the pattern from API
		_, baseModelURL, err := getFirstAvailableModel(tempToken, apiBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		// For custom model names, construct URL based on API pattern
		baseURL := strings.Split(baseModelURL, "/llm/")[0]
		modelURLPart := strings.ReplaceAll(modelName, "/", "-") + "-simulated"
		modelURL = baseURL + "/llm/" + modelURLPart + "/v1/chat/completions"
	}
	payload := map[string]interface{}{
		"model":      modelName,
		"prompt":     "Hello",
		"max_tokens": 50,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode request: %v\n", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, modelURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to build request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// NOTE: Deliberately NOT setting Authorization header

	if ctx.showCurl {
		printCurlCommand(req)
		return
	}

	client := newAPIClient(true)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("✓ Authorization test completed\n")
	fmt.Printf("Model: %s\n", modelName)
	fmt.Printf("Status: %s\n", resp.Status)

	if resp.StatusCode == 401 {
		fmt.Printf("✓ Expected 401 Unauthorized - authorization is working correctly\n")
	} else {
		fmt.Printf("⚠ Expected 401 but got %s - authorization may not be configured properly\n", resp.Status)
	}

	// Show response body for debugging
	if body, err := io.ReadAll(io.LimitReader(resp.Body, 4096)); err == nil {
		if len(body) > 0 {
			fmt.Printf("Response: %s\n", strings.TrimSpace(string(body)))
		}
	}
}

func handleTestRateLimitBase(ctx *commandContext) {
	// Parse model name argument
	args := strings.Fields(ctx.args)
	var modelName string
	if len(args) > 0 {
		modelName = args[0]
	}

	// Get stored service account token
	serviceToken, apiBase, err := ensureBaseToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// If no model specified, get the first available model
	var modelURL string
	if modelName == "" {
		modelName, modelURL, err = getFirstAvailableModel(serviceToken, apiBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
	} else {
		// For provided model name, construct URL using the pattern from API
		_, baseModelURL, err := getFirstAvailableModel(serviceToken, apiBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		// For custom model names, construct URL based on API pattern
		baseURL := strings.Split(baseModelURL, "/llm/")[0]
		modelURLPart := strings.ReplaceAll(modelName, "/", "-") + "-simulated"
		modelURL = baseURL + "/llm/" + modelURLPart + "/v1/chat/completions"
	}
	payload := map[string]interface{}{
		"model":      modelName,
		"prompt":     "Hello",
		"max_tokens": 50,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to encode request: %v\n", err)
		return
	}

	// If showing curl, just show one request
	if ctx.showCurl {
		req, err := http.NewRequest(http.MethodPost, modelURL, bytes.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to build request: %v\n", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+serviceToken)
		req.Header.Set("Content-Type", "application/json")

		fmt.Println("# Rate limit test - run this command 16 times rapidly:")
		printCurlCommand(req)
		return
	}

	client := newAPIClient(true)

	fmt.Printf("✓ Rate limit test starting\n")
	fmt.Printf("Model: %s\n", modelName)
	fmt.Printf("Sending 16 concurrent requests...\n\n")

	// Send 16 requests as per validation script
	for i := 1; i <= 16; i++ {
		req, err := http.NewRequest(http.MethodPost, modelURL, bytes.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to build request %d: %v\n", i, err)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+serviceToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Request %2d: ERROR - %v\n", i, err)
			continue
		}

		fmt.Printf("Request %2d: %s\n", i, resp.Status)
		resp.Body.Close()

		// Small delay between requests
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("\n✓ Rate limit test completed\n")
	fmt.Printf("Expected: First ~4 requests should be 200 OK, then 429 Rate Limit Exceeded\n")
}

func handleValidateBase(ctx *commandContext) {
	fmt.Println("🔍 MaaS Deployment Validation")
	fmt.Println("═══════════════════════════════")

	// Step 1: Get gateway endpoint
	fmt.Println("\n1. Getting gateway endpoint...")
	domain, err := getClusterDomainBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ❌ Failed: %v\n", err)
		return
	}
	endpoint := fmt.Sprintf("maas.%s", domain)
	fmt.Printf("   ✓ Gateway: %s\n", endpoint)

	// Step 2: Check for stored service account token
	fmt.Println("\n2. Checking service account token...")
	serviceToken, apiBase, err := ensureBaseToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ❌ Failed: %v\n", err)
		fmt.Println("   💡 Run /get-token first to create a service account token")
		return
	}
	fmt.Printf("   ✓ Service token available (length: %d)\n", len(serviceToken))

	// Step 3: Test model endpoint
	fmt.Println("\n3. Testing model endpoint...")

	// Get models first
	modelsReq, _ := http.NewRequest(http.MethodGet, apiBase+"/maas-api/v1/models", nil)
	modelsReq.Header.Set("Authorization", "Bearer "+serviceToken)
	modelsReq.Header.Set("Content-Type", "application/json")

	client := newAPIClient(true)
	resp, err := client.Do(modelsReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ❌ Models request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "   ❌ Models request failed: %s\n", resp.Status)
		return
	}

	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		fmt.Fprintf(os.Stderr, "   ❌ Failed to decode models response: %v\n", err)
		return
	}

	if len(payload.Data) == 0 {
		fmt.Println("   ❌ No models available")
		return
	}

	modelName := payload.Data[0].ID
	fmt.Printf("   ✓ Using model: %s\n", modelName)

	// Test model inference - use the helper function to get correct URL
	_, modelURL, err := getFirstAvailableModel(serviceToken, apiBase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ❌ Failed to get model URL: %v\n", err)
		return
	}
	testPayload := map[string]interface{}{
		"model":      modelName,
		"prompt":     "Hello",
		"max_tokens": 50,
	}

	body, _ := json.Marshal(testPayload)
	testReq, _ := http.NewRequest(http.MethodPost, modelURL, bytes.NewReader(body))
	testReq.Header.Set("Authorization", "Bearer "+serviceToken)
	testReq.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(testReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ❌ Model test failed: %v\n", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "   ❌ Model test failed: %s\n", resp.Status)
		return
	}
	fmt.Printf("   ✓ Model inference successful: %s\n", resp.Status)

	// Step 4: Test authorization limiting
	fmt.Println("\n4. Testing authorization limiting...")
	noAuthReq, _ := http.NewRequest(http.MethodPost, modelURL, bytes.NewReader(body))
	noAuthReq.Header.Set("Content-Type", "application/json")
	// No Authorization header

	resp, err = client.Do(noAuthReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ❌ Auth test failed: %v\n", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode == 401 {
		fmt.Printf("   ✓ Authorization working: %s\n", resp.Status)
	} else {
		fmt.Printf("   ⚠ Expected 401, got %s\n", resp.Status)
	}

	// Step 5: Test rate limiting
	fmt.Println("\n5. Testing rate limiting...")
	okCount := 0
	limitedCount := 0

	for i := 1; i <= 16; i++ {
		req, _ := http.NewRequest(http.MethodPost, modelURL, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+serviceToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			okCount++
		} else if resp.StatusCode == 429 {
			limitedCount++
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("   ✓ Sent 16 requests: %d successful, %d rate limited\n", okCount, limitedCount)
	if limitedCount > 0 {
		fmt.Printf("   ✓ Rate limiting is working\n")
	} else {
		fmt.Printf("   ⚠ No rate limiting detected\n")
	}

	fmt.Println("\n🎉 Validation completed!")
	fmt.Printf("   Gateway: https://%s\n", endpoint)
	fmt.Printf("   Model: %s\n", modelName)
	fmt.Printf("   Auth: %s\n", map[bool]string{true: "✓ Working", false: "⚠ Check configuration"}[resp.StatusCode == 401])
	fmt.Printf("   Rate limiting: %s\n", map[bool]string{true: "✓ Working", false: "⚠ Not detected"}[limitedCount > 0])
}

func handleLoginBase(ctx *commandContext) {
	fmt.Println("MaaS CLI - Base Authentication")
	fmt.Println("──────────────────────────────")
	fmt.Println("In base mode, authentication uses OpenShift tokens.")
	fmt.Println("Make sure you're logged into OpenShift with 'oc login'")
	fmt.Println("Then run /get-token to create a service account token for API access.")

	// Test OpenShift connectivity
	if _, err := getOpenShiftTokenBase(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ Warning: %v\n", err)
		fmt.Println("Please run 'oc login' first to authenticate with OpenShift.")
	} else {
		fmt.Println("✓ OpenShift connection verified")
		fmt.Println("You can now run /get-token to create a service account token.")
	}
}

func handleMetricsBase(ctx *commandContext) {
	fmt.Println("Metrics viewing functionality")
}
