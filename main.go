package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	prompt "github.com/c-bata/go-prompt"
)

const (
	envMaasAPIURL = "MAAS_API_URL"
	envAPIKey     = "MAAS_API_KEY"
	envOCToken    = "OC_TOKEN"

	cliBanner = `
 ███░   ███░ █████░  █████░ ███████░     ██████░██░     ██░
 ████░ ████░██░░░██░██░░░██░██░░░░░░    ██░░░░░░██░     ██░
 ██░████░██░███████░███████░███████░    ██░     ██░     ██░
 ██░░██░░██░██░░░██░██░░░██░░░░░░██░    ██░     ██░     ██░
 ██░ ░░░ ██░██░  ██░██░  ██░███████░    ░██████░███████░██░
 ░░░      ░░░░░   ░░░░░   ░░░░░░░░░░      ░░░░░░░░░░░░░░░░░`
)

// ── Session ─────────────────────────────────────────────────────────────────

type session struct {
	MaasAPIURL   string `json:"maas_api_url,omitempty"`
	APIKey       string `json:"api_key,omitempty"`
	APIKeyID     string `json:"api_key_id,omitempty"`
	Subscription string `json:"subscription,omitempty"`
	LastModelID  string `json:"last_model_id,omitempty"`
	LastModelURL string `json:"last_model_url,omitempty"`
}

// ── Request / Response types ────────────────────────────────────────────────

type apiKeyCreateRequest struct {
	Name         string `json:"name,omitempty"`
	Description  string `json:"description,omitempty"`
	ExpiresIn    string `json:"expiresIn,omitempty"`
	Subscription string `json:"subscription,omitempty"`
	Ephemeral    bool   `json:"ephemeral,omitempty"`
}

type apiKeyCreateResponse struct {
	ID           string `json:"id"`
	Key          string `json:"key"`
	KeyPrefix    string `json:"keyPrefix"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Subscription string `json:"subscription"`
	CreatedAt    string `json:"createdAt"`
	ExpiresAt    string `json:"expiresAt"`
	Ephemeral    bool   `json:"ephemeral"`
	Status       string `json:"status"`
}

type modelInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type modelsResponse struct {
	Data []modelInfo `json:"data"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens,omitempty"`
	Stream    bool          `json:"stream,omitempty"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
}

// ── main ────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		startREPL()
		return
	}

	var err error
	switch os.Args[1] {
	case "endpoint":
		err = runEndpoint(os.Args[2:])
	case "create-api-key":
		err = runCreateAPIKey(os.Args[2:])
	case "revoke-api-key":
		err = runRevokeAPIKey(os.Args[2:])
	case "list-api-keys":
		err = runListAPIKeys(os.Args[2:])
	case "models":
		err = runModels(os.Args[2:])
	case "subscriptions":
		err = runSubscriptions(os.Args[2:])
	case "chat":
		err = runChat(os.Args[2:])
	case "help", "-h", "--help":
		printRootUsage()
		return
	default:
		printRootUsage()
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ── REPL ────────────────────────────────────────────────────────────────────

// chatHistory holds the multi-turn conversation for /chat within the REPL.
var chatHistory []chatMessage

// chatState holds resolved chat config so we don't re-discover every message.
var chatState struct {
	ready   bool
	chatURL string
	modelID string
	apiKey  string
}

var replCommands = []prompt.Suggest{
	{Text: "/endpoint", Description: "Detect MaaS API URL from cluster"},
	{Text: "/create-api-key", Description: "Create an API key"},
	{Text: "/revoke-api-key", Description: "Revoke an API key"},
	{Text: "/list-api-keys", Description: "Search/list API keys"},
	{Text: "/subscriptions", Description: "List accessible subscriptions"},
	{Text: "/models", Description: "List available models"},
	{Text: "/chat", Description: "Send a message: /chat hello!"},
	{Text: "/chat-clear", Description: "Clear chat history"},
	{Text: "/chat-history", Description: "Show chat history"},
	{Text: "/session", Description: "Show current session state"},
	{Text: "/help", Description: "Show available commands"},
	{Text: "/exit", Description: "Quit"},
}

func replCompleter(d prompt.Document) []prompt.Suggest {
	text := d.TextBeforeCursor()
	if text == "" {
		return nil
	}
	// Only suggest on the first word
	if strings.Contains(strings.TrimLeft(text, "/"), " ") {
		return nil
	}
	return prompt.FilterHasPrefix(replCommands, text, true)
}

func replExecutor(input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}

	parts := strings.Fields(input)
	cmd := parts[0]
	args := parts[1:]

	// Strip leading / for command matching
	cmdName := strings.TrimPrefix(cmd, "/")

	// Resolve partial commands (e.g. "/en" -> "endpoint", "/mo" -> "models")
	cmdName = resolveCommand(cmdName)

	var err error
	switch cmdName {
	case "endpoint":
		err = runEndpoint(args)
	case "create-api-key":
		err = runCreateAPIKey(args)
	case "revoke-api-key":
		err = runRevokeAPIKey(args)
	case "list-api-keys":
		err = runListAPIKeys(args)
	case "models":
		err = runModels(args)
	case "subscriptions":
		err = runSubscriptions(args)
	case "chat":
		msg := strings.Join(args, " ")
		if msg == "" {
			fmt.Println("Usage: /chat <message>")
			fmt.Println("  Multi-turn history is kept automatically.")
			fmt.Println("  /chat-clear to reset, /chat-history to review.")
			return
		}
		err = replChat(msg)
	case "chat-clear":
		chatHistory = nil
		chatState.ready = false
		fmt.Println("Chat history cleared.")
	case "chat-history":
		if len(chatHistory) == 0 {
			fmt.Println("No chat history. Send a message with /chat <message>")
		} else {
			for _, m := range chatHistory {
				fmt.Printf("[%s] %s\n", m.Role, m.Content)
			}
		}
	case "session":
		err = showSession()
	case "help", "h":
		printREPLHelp()
	case "exit", "quit", "q":
		fmt.Println("Goodbye!")
		restoreTerminal()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s (type /help for commands)\n", cmd)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

var commandNames = []string{
	"endpoint", "create-api-key", "revoke-api-key", "list-api-keys",
	"models", "subscriptions", "chat", "chat-clear", "chat-history",
	"session", "help", "exit", "quit",
}

func replChat(message string) error {
	// Lazy-init: resolve model URL and API key on first /chat message
	if !chatState.ready {
		sess, _ := loadSession()
		key, err := resolveAPIKey("", sess)
		if err != nil {
			return fmt.Errorf("no API key — run /create-api-key first: %w", err)
		}
		chatState.apiKey = key

		modelURL := ""
		modelID := ""
		if sess != nil {
			modelURL = strings.TrimSpace(sess.LastModelURL)
			modelID = strings.TrimSpace(sess.LastModelID)
		}

		if modelURL == "" {
			// Discover via /v1/models (needs OC token)
			apiURL, err := resolveMaasAPIURL("", sess)
			if err != nil {
				return err
			}
			token, err := resolveOCToken("")
			if err != nil {
				return fmt.Errorf("model discovery needs an OpenShift token: %w", err)
			}
			models, _, _, err := fetchModels(apiURL, token, "")
			if err != nil {
				return fmt.Errorf("failed to discover models: %w", err)
			}
			if len(models.Data) == 0 {
				return errors.New("no models available — check /models")
			}
			modelURL = models.Data[0].URL
			modelID = models.Data[0].ID

			// Save for next time
			if sess == nil {
				sess = &session{}
			}
			sess.LastModelURL = modelURL
			sess.LastModelID = modelID
			_ = saveSession(sess)
		}

		chatURL, err := ensureChatCompletionsURL(modelURL)
		if err != nil {
			return err
		}
		chatState.chatURL = chatURL
		chatState.modelID = modelID
		chatState.ready = true

		fmt.Printf("  Model: %s\n", chatState.modelID)
		fmt.Printf("  URL:   %s\n", chatState.chatURL)
		fmt.Println()
	}

	chatHistory = append(chatHistory, chatMessage{Role: "user", Content: message})

	content, err := sendChatMessage(chatState.chatURL, chatState.modelID, chatState.apiKey,
		chatHistory, 100, false, false, false)
	if err != nil {
		chatHistory = chatHistory[:len(chatHistory)-1]
		return err
	}

	chatHistory = append(chatHistory, chatMessage{Role: "assistant", Content: content})
	fmt.Printf("assistant> %s\n", content)
	return nil
}

func resolveCommand(input string) string {
	// Exact match first
	for _, c := range commandNames {
		if input == c {
			return c
		}
	}
	// Unique prefix match
	var match string
	for _, c := range commandNames {
		if strings.HasPrefix(c, input) {
			if match != "" {
				// Ambiguous — return original, let the switch hit default
				return input
			}
			match = c
		}
	}
	if match != "" {
		return match
	}
	return input
}

func containsFlag(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f || a == "-"+f || a == "--"+strings.TrimPrefix(f, "-") {
				return true
			}
		}
	}
	return false
}

func showSession() error {
	sess, err := loadSession()
	if err != nil {
		return err
	}
	if sess == nil {
		fmt.Println("No session saved. Run /create-api-key to get started.")
		return nil
	}
	out, _ := json.MarshalIndent(sess, "", "  ")
	fmt.Println(string(out))
	return nil
}

func printREPLBanner() {
	fmt.Println(cliBanner)
	fmt.Println()

	sess, _ := loadSession()
	if sess != nil && sess.MaasAPIURL != "" {
		fmt.Printf("  Endpoint: %s\n", sess.MaasAPIURL)
	}
	if sess != nil && sess.APIKey != "" {
		prefix := sess.APIKey
		if len(prefix) > 20 {
			prefix = prefix[:20]
		}
		fmt.Printf("  API Key:  %s...\n", prefix)
	}
	if sess != nil && sess.LastModelID != "" {
		fmt.Printf("  Model:    %s\n", sess.LastModelID)
	}
	fmt.Println()
	fmt.Println("  Type / to see commands, /help for details, /exit or Ctrl-D to quit.")
	fmt.Println()
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func startREPL() {
	printREPLBanner()

	if !isTTY() {
		// Fallback: basic line reader when stdin is piped
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("maas> ")
			if !scanner.Scan() {
				break
			}
			replExecutor(scanner.Text())
		}
		return
	}

	p := prompt.New(
		replExecutor,
		replCompleter,
		prompt.OptionPrefix("maas> "),
		prompt.OptionTitle("MaaS CLI"),
		prompt.OptionPrefixTextColor(prompt.Cyan),
		prompt.OptionSuggestionBGColor(prompt.DarkGray),
		prompt.OptionSelectedSuggestionBGColor(prompt.Cyan),
		prompt.OptionDescriptionBGColor(prompt.DarkGray),
		prompt.OptionSelectedDescriptionBGColor(prompt.Cyan),
	)
	p.Run()

	// go-prompt exits here on Ctrl-D
	fmt.Println("Goodbye!")
	restoreTerminal()
}

func restoreTerminal() {
	cmd := exec.Command("stty", "sane")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func printREPLHelp() {
	fmt.Println("Commands:")
	fmt.Println("  /endpoint          Detect MaaS API URL from cluster")
	fmt.Println("  /create-api-key    Create an API key (+ flags like --name, --expires-in)")
	fmt.Println("  /revoke-api-key    Revoke an API key (--key-id)")
	fmt.Println("  /list-api-keys     Search/list your API keys")
	fmt.Println("  /subscriptions     List accessible subscriptions")
	fmt.Println("  /models            List available models")
	fmt.Println("  /chat <message>    Send a chat message (multi-turn history kept)")
	fmt.Println("  /chat-clear        Clear chat conversation history")
	fmt.Println("  /chat-history      Show chat conversation so far")
	fmt.Println("  /session           Show current session state")
	fmt.Println("  /help              Show this help")
	fmt.Println("  /exit, Ctrl-D      Quit")
	fmt.Println()
	fmt.Println("Append --show-curl to any command to see the equivalent curl.")
	fmt.Println("Append --help to any command for flag details.")
}

// ── endpoint ────────────────────────────────────────────────────────────────

func runEndpoint(args []string) error {
	fs := flag.NewFlagSet("endpoint", flag.ContinueOnError)
	showCurl := fs.Bool("show-curl", false, "print the kubectl command and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *showCurl {
		fmt.Println("kubectl get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'")
		return nil
	}

	domain, err := detectClusterDomain()
	if err != nil {
		return err
	}

	fmt.Printf("https://maas.%s\n", domain)
	return nil
}

// ── create-api-key ──────────────────────────────────────────────────────────

func runCreateAPIKey(args []string) error {
	fs := flag.NewFlagSet("create-api-key", flag.ContinueOnError)
	maasAPIURL := fs.String("maas-api-url", "", "MaaS API URL (defaults to MAAS_API_URL, saved session, or auto-detect)")
	ocToken := fs.String("oc-token", "", "OpenShift token (defaults to OC_TOKEN or oc whoami -t)")
	name := fs.String("name", "maas-cli-key", "API key name (required for non-ephemeral keys)")
	description := fs.String("description", "Created by maas-cli", "API key description")
	expiresIn := fs.String("expires-in", "", "Key expiration, e.g. 90d, 30d, 1h")
	subscription := fs.String("subscription", "", "MaaSSubscription name to bind this key")
	ephemeral := fs.Bool("ephemeral", false, "Create an ephemeral key (max 1h)")
	showCurl := fs.Bool("show-curl", false, "print equivalent curl and exit")
	noSave := fs.Bool("no-save", false, "do not save key/API URL to session")
	raw := fs.Bool("raw", false, "print raw JSON response")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	sess, _ := loadSession()
	apiURL, err := resolveMaasAPIURL(*maasAPIURL, sess)
	if err != nil {
		return err
	}

	token, err := resolveOCToken(*ocToken)
	if err != nil {
		return err
	}

	payload := apiKeyCreateRequest{
		Name:         strings.TrimSpace(*name),
		Description:  strings.TrimSpace(*description),
		ExpiresIn:    strings.TrimSpace(*expiresIn),
		Subscription: strings.TrimSpace(*subscription),
		Ephemeral:    *ephemeral,
	}

	if !payload.Ephemeral && payload.Name == "" {
		return errors.New("--name is required for non-ephemeral keys")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoint, err := url.JoinPath(strings.TrimRight(apiURL, "/"), "maas-api", "v1", "api-keys")
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	if *showCurl {
		fmt.Println(curlForRequest(req, body, false))
		return nil
	}

	respBody, err := doRequest(req)
	if err != nil {
		return err
	}

	if *raw {
		fmt.Println(string(respBody))
	} else {
		prettyPrintJSON(respBody)
	}

	var created apiKeyCreateResponse
	if err := json.Unmarshal(respBody, &created); err == nil && !*noSave {
		if sess == nil {
			sess = &session{}
		}
		sess.MaasAPIURL = apiURL
		sess.APIKey = created.Key
		sess.APIKeyID = created.ID
		sess.Subscription = created.Subscription
		if err := saveSession(sess); err != nil {
			return fmt.Errorf("key created, but failed to save session: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Saved API URL and API key in ~/.maas-cli/session.json")
	}

	return nil
}

// ── revoke-api-key ──────────────────────────────────────────────────────────

func runRevokeAPIKey(args []string) error {
	fs := flag.NewFlagSet("revoke-api-key", flag.ContinueOnError)
	maasAPIURL := fs.String("maas-api-url", "", "MaaS API URL")
	ocToken := fs.String("oc-token", "", "OpenShift token (defaults to OC_TOKEN or oc whoami -t)")
	keyID := fs.String("key-id", "", "API key ID to revoke (defaults to last created key from session)")
	showCurl := fs.Bool("show-curl", false, "print equivalent curl and exit")
	raw := fs.Bool("raw", false, "print raw JSON response")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	sess, _ := loadSession()
	apiURL, err := resolveMaasAPIURL(*maasAPIURL, sess)
	if err != nil {
		return err
	}

	token, err := resolveOCToken(*ocToken)
	if err != nil {
		return err
	}

	id := strings.TrimSpace(*keyID)
	if id == "" && sess != nil {
		id = sess.APIKeyID
	}
	if id == "" {
		return errors.New("--key-id is required (no saved key ID in session)")
	}

	endpoint, err := url.JoinPath(strings.TrimRight(apiURL, "/"), "maas-api", "v1", "api-keys", id)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	if *showCurl {
		fmt.Println(curlForRequest(req, nil, false))
		return nil
	}

	respBody, err := doRequest(req)
	if err != nil {
		return err
	}

	if *raw {
		fmt.Println(string(respBody))
	} else {
		prettyPrintJSON(respBody)
	}

	// Clear session key if we just revoked it
	if sess != nil && sess.APIKeyID == id {
		sess.APIKey = ""
		sess.APIKeyID = ""
		_ = saveSession(sess)
		fmt.Fprintln(os.Stderr, "Cleared revoked key from session")
	}

	return nil
}

// ── list-api-keys ───────────────────────────────────────────────────────────

func runListAPIKeys(args []string) error {
	fs := flag.NewFlagSet("list-api-keys", flag.ContinueOnError)
	maasAPIURL := fs.String("maas-api-url", "", "MaaS API URL")
	ocToken := fs.String("oc-token", "", "OpenShift token (defaults to OC_TOKEN or oc whoami -t)")
	status := fs.String("status", "active", "Filter by status: active, revoked, expired (comma-separated)")
	includeEphemeral := fs.Bool("include-ephemeral", false, "Include ephemeral keys")
	sortBy := fs.String("sort-by", "created_at", "Sort by: created_at, expires_at, last_used_at, name")
	sortOrder := fs.String("sort-order", "desc", "Sort order: asc, desc")
	limit := fs.Int("limit", 50, "Max results (1-100)")
	offset := fs.Int("offset", 0, "Pagination offset")
	showCurl := fs.Bool("show-curl", false, "print equivalent curl and exit")
	raw := fs.Bool("raw", false, "print raw JSON response")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	sess, _ := loadSession()
	apiURL, err := resolveMaasAPIURL(*maasAPIURL, sess)
	if err != nil {
		return err
	}

	token, err := resolveOCToken(*ocToken)
	if err != nil {
		return err
	}

	// Build search request body
	statuses := strings.Split(*status, ",")
	for i := range statuses {
		statuses[i] = strings.TrimSpace(statuses[i])
	}

	searchBody := map[string]any{
		"filters": map[string]any{
			"status":           statuses,
			"includeEphemeral": *includeEphemeral,
		},
		"sort": map[string]any{
			"by":    *sortBy,
			"order": *sortOrder,
		},
		"pagination": map[string]any{
			"limit":  *limit,
			"offset": *offset,
		},
	}

	body, err := json.Marshal(searchBody)
	if err != nil {
		return err
	}

	endpoint, err := url.JoinPath(strings.TrimRight(apiURL, "/"), "maas-api", "v1", "api-keys", "search")
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	if *showCurl {
		fmt.Println(curlForRequest(req, body, false))
		return nil
	}

	respBody, err := doRequest(req)
	if err != nil {
		return err
	}

	if *raw {
		fmt.Println(string(respBody))
	} else {
		prettyPrintJSON(respBody)
	}

	return nil
}

// ── subscriptions ───────────────────────────────────────────────────────────

func runSubscriptions(args []string) error {
	fs := flag.NewFlagSet("subscriptions", flag.ContinueOnError)
	maasAPIURL := fs.String("maas-api-url", "", "MaaS API URL")
	apiKey := fs.String("api-key", "", "API key (defaults to MAAS_API_KEY or saved session)")
	ocToken := fs.String("oc-token", "", "OpenShift token (alternative to API key)")
	modelID := fs.String("model-id", "", "Filter subscriptions for a specific model")
	showCurl := fs.Bool("show-curl", false, "print equivalent curl and exit")
	raw := fs.Bool("raw", false, "print raw JSON response")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	sess, _ := loadSession()
	apiURL, err := resolveMaasAPIURL(*maasAPIURL, sess)
	if err != nil {
		return err
	}

	// Try API key first, fall back to OC token
	var authToken string
	resolvedKey, keyErr := resolveAPIKey(*apiKey, sess)
	if keyErr == nil {
		authToken = resolvedKey
	} else {
		authToken, err = resolveOCToken(*ocToken)
		if err != nil {
			return fmt.Errorf("need --api-key or --oc-token: %w", keyErr)
		}
	}

	var pathParts []string
	if mid := strings.TrimSpace(*modelID); mid != "" {
		pathParts = []string{"maas-api", "v1", "model", mid, "subscriptions"}
	} else {
		pathParts = []string{"maas-api", "v1", "subscriptions"}
	}

	endpoint, err := url.JoinPath(strings.TrimRight(apiURL, "/"), pathParts...)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Content-Type", "application/json")

	if *showCurl {
		fmt.Println(curlForRequest(req, nil, false))
		return nil
	}

	respBody, err := doRequest(req)
	if err != nil {
		return err
	}

	if *raw {
		fmt.Println(string(respBody))
	} else {
		prettyPrintJSON(respBody)
	}

	return nil
}

// ── models ──────────────────────────────────────────────────────────────────

func runModels(args []string) error {
	fs := flag.NewFlagSet("models", flag.ContinueOnError)
	maasAPIURL := fs.String("maas-api-url", "", "MaaS API URL (defaults to MAAS_API_URL or saved session)")
	ocToken := fs.String("oc-token", "", "OpenShift token (defaults to OC_TOKEN or oc whoami -t)")
	subscription := fs.String("subscription", "", "X-MaaS-Subscription header")
	showCurl := fs.Bool("show-curl", false, "print equivalent curl and exit")
	raw := fs.Bool("raw", false, "print raw JSON response")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	sess, _ := loadSession()
	token, err := resolveOCToken(*ocToken)
	if err != nil {
		return err
	}
	apiURL, err := resolveMaasAPIURL(*maasAPIURL, sess)
	if err != nil {
		return err
	}

	req, err := buildModelsRequest(apiURL, token, strings.TrimSpace(*subscription))
	if err != nil {
		return err
	}

	if *showCurl {
		fmt.Println(curlForRequest(req, nil, false))
		return nil
	}

	models, rawResp, err := executeModelsRequest(req)
	if err != nil {
		return err
	}

	if *raw {
		fmt.Println(string(rawResp))
	} else {
		prettyPrintJSON(rawResp)
	}

	if len(models.Data) > 0 {
		if sess == nil {
			sess = &session{}
		}
		sess.MaasAPIURL = apiURL
		sess.LastModelID = models.Data[0].ID
		sess.LastModelURL = models.Data[0].URL
		_ = saveSession(sess)
	}

	return nil
}

// ── chat ────────────────────────────────────────────────────────────────────

func runChat(args []string) error {
	fs := flag.NewFlagSet("chat", flag.ContinueOnError)
	maasAPIURL := fs.String("maas-api-url", "", "MaaS API URL")
	apiKey := fs.String("api-key", "", "API key (defaults to MAAS_API_KEY or saved session)")
	ocToken := fs.String("oc-token", "", "OpenShift token for model discovery (defaults to OC_TOKEN or oc whoami -t)")
	modelID := fs.String("model-id", "", "Model ID from /v1/models")
	modelURL := fs.String("model-url", "", "Explicit model URL (if omitted, resolve via /v1/models)")
	prompt := fs.String("prompt", "", "User prompt text (omit for interactive mode)")
	maxTokens := fs.Int("max-tokens", 100, "max tokens")
	stream := fs.Bool("stream", false, "enable streaming response")
	interactive := fs.Bool("interactive", false, "multi-turn interactive chat mode")
	showCurl := fs.Bool("show-curl", false, "print equivalent curl and exit")
	raw := fs.Bool("raw", false, "print raw response body")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	sess, _ := loadSession()
	resolvedAPIKey, err := resolveAPIKey(*apiKey, sess)
	if err != nil {
		return err
	}
	apiURL := ""

	selectedModelID := strings.TrimSpace(*modelID)
	selectedModelURL := strings.TrimSpace(*modelURL)

	// Try session for model URL/ID
	if selectedModelURL == "" && sess != nil && strings.TrimSpace(sess.LastModelURL) != "" {
		selectedModelURL = strings.TrimSpace(sess.LastModelURL)
		if selectedModelID == "" {
			selectedModelID = strings.TrimSpace(sess.LastModelID)
		}
	}

	if selectedModelURL == "" {
		if *showCurl {
			return errors.New("--model-url is required with --show-curl when no saved model URL exists")
		}
		apiURL, err = resolveMaasAPIURL(*maasAPIURL, sess)
		if err != nil {
			return err
		}
		// /v1/models requires OC token auth (not API key)
		discoverToken, tokenErr := resolveOCToken(*ocToken)
		if tokenErr != nil {
			return fmt.Errorf("model discovery requires an OpenShift token: %w", tokenErr)
		}
		models, _, _, err := fetchModels(apiURL, discoverToken, "")
		if err != nil {
			return fmt.Errorf("failed to resolve model URL from /v1/models: %w", err)
		}
		if len(models.Data) == 0 {
			return errors.New("/v1/models returned no models")
		}

		chosen := models.Data[0]
		if selectedModelID != "" {
			found := false
			for _, m := range models.Data {
				if m.ID == selectedModelID {
					chosen = m
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("model-id %q not found in /v1/models", selectedModelID)
			}
		}

		selectedModelID = chosen.ID
		selectedModelURL = chosen.URL
	}

	if selectedModelID == "" {
		if sess != nil && sess.LastModelID != "" {
			selectedModelID = sess.LastModelID
		} else {
			selectedModelID = "auto"
		}
	}

	chatURL, err := ensureChatCompletionsURL(selectedModelURL)
	if err != nil {
		return err
	}

	// Decide mode: interactive, single prompt, or error
	if *interactive || (*prompt == "" && !*showCurl) {
		return runInteractiveChat(chatURL, selectedModelID, resolvedAPIKey, *maxTokens, *stream, *raw)
	}

	if *prompt == "" && *showCurl {
		*prompt = "Hello, how are you?"
	}

	// Single-shot chat
	respContent, err := sendChatMessage(chatURL, selectedModelID, resolvedAPIKey,
		[]chatMessage{{Role: "user", Content: *prompt}},
		*maxTokens, *stream, *raw, *showCurl)
	if err != nil {
		return err
	}
	if !*showCurl {
		fmt.Println(respContent)
	}

	// Save session
	if sess == nil {
		sess = &session{}
	}
	if apiURL != "" {
		sess.MaasAPIURL = apiURL
	}
	sess.APIKey = resolvedAPIKey
	sess.LastModelID = selectedModelID
	sess.LastModelURL = selectedModelURL
	_ = saveSession(sess)

	return nil
}

// ── interactive chat ────────────────────────────────────────────────────────

func runInteractiveChat(chatURL, modelID, apiKey string, maxTokens int, stream, raw bool) error {
	fmt.Println(cliBanner)
	fmt.Println()
	fmt.Printf("  Model: %s\n", modelID)
	fmt.Printf("  URL:   %s\n", chatURL)
	fmt.Println()
	fmt.Println("  Type your message and press Enter. Type /quit to exit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	var history []chatMessage

	for {
		fmt.Print("you> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}
		if input == "/quit" || input == "/exit" || input == "/q" {
			fmt.Println("Goodbye!")
			break
		}
		if input == "/clear" {
			history = nil
			fmt.Println("(conversation cleared)")
			continue
		}
		if input == "/history" {
			for _, m := range history {
				fmt.Printf("[%s] %s\n", m.Role, m.Content)
			}
			continue
		}

		history = append(history, chatMessage{Role: "user", Content: input})

		content, err := sendChatMessage(chatURL, modelID, apiKey, history, maxTokens, stream, raw, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			// Remove the failed user message from history
			history = history[:len(history)-1]
			continue
		}

		history = append(history, chatMessage{Role: "assistant", Content: content})
		fmt.Printf("assistant> %s\n\n", content)
	}

	return nil
}

// sendChatMessage sends a chat request and returns the assistant content.
// If showCurl is true, it prints the curl command and returns "".
func sendChatMessage(chatURL, modelID, apiKey string, messages []chatMessage, maxTokens int, stream, raw, showCurl bool) (string, error) {
	payload := chatRequest{
		Model:     modelID,
		Messages:  messages,
		MaxTokens: maxTokens,
		Stream:    stream,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, chatURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	if showCurl {
		fmt.Println(curlForRequest(req, body, stream))
		return "", nil
	}

	client := newHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("chat request failed (%s): %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	if stream {
		// Stream raw SSE to stdout
		if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
			return "", err
		}
		fmt.Println()
		return "(streamed)", nil
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}

	if raw {
		fmt.Println(string(respBody))
		return "", nil
	}

	// Parse and extract assistant content
	var cr chatResponse
	if err := json.Unmarshal(respBody, &cr); err != nil {
		// Fall back to pretty JSON if parsing fails
		prettyPrintJSON(respBody)
		return "", nil
	}

	if len(cr.Choices) > 0 && cr.Choices[0].Message.Content != "" {
		return cr.Choices[0].Message.Content, nil
	}

	// Fallback: print full response
	prettyPrintJSON(respBody)
	return "", nil
}

// ── helpers: model resolution ───────────────────────────────────────────────

func fetchModels(apiURL, apiKey, subscription string) (*modelsResponse, []byte, *http.Request, error) {
	req, err := buildModelsRequest(apiURL, apiKey, subscription)
	if err != nil {
		return nil, nil, nil, err
	}

	models, respBody, err := executeModelsRequest(req)
	if err != nil {
		return nil, nil, req, err
	}

	return models, respBody, req, nil
}

func buildModelsRequest(apiURL, apiKey, subscription string) (*http.Request, error) {
	endpoint, err := url.JoinPath(strings.TrimRight(apiURL, "/"), "v1", "models")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	if subscription != "" {
		req.Header.Set("X-MaaS-Subscription", subscription)
	}

	return req, nil
}

func executeModelsRequest(req *http.Request) (*modelsResponse, []byte, error) {
	respBody, err := doRequest(req)
	if err != nil {
		return nil, nil, err
	}

	var payload modelsResponse
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, nil, fmt.Errorf("failed to decode /v1/models response: %w", err)
	}

	return &payload, respBody, nil
}

func ensureChatCompletionsURL(modelURL string) (string, error) {
	t := strings.TrimSpace(modelURL)
	if t == "" {
		return "", errors.New("empty model URL")
	}
	if strings.Contains(t, "/v1/chat/completions") {
		return t, nil
	}
	joined, err := url.JoinPath(strings.TrimRight(t, "/"), "v1", "chat", "completions")
	if err != nil {
		return "", err
	}
	return joined, nil
}

// ── helpers: resolution ─────────────────────────────────────────────────────

func resolveMaasAPIURL(explicit string, sess *session) (string, error) {
	if u := strings.TrimSpace(explicit); u != "" {
		return strings.TrimRight(u, "/"), nil
	}
	if u := strings.TrimSpace(os.Getenv(envMaasAPIURL)); u != "" {
		return strings.TrimRight(u, "/"), nil
	}
	if sess != nil && strings.TrimSpace(sess.MaasAPIURL) != "" {
		return strings.TrimRight(sess.MaasAPIURL, "/"), nil
	}
	domain, err := detectClusterDomain()
	if err != nil {
		return "", fmt.Errorf("unable to resolve MaaS API URL (set --maas-api-url or %s): %w", envMaasAPIURL, err)
	}
	return "https://maas." + domain, nil
}

func resolveAPIKey(explicit string, sess *session) (string, error) {
	if v := strings.TrimSpace(explicit); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv(envAPIKey)); v != "" {
		return v, nil
	}
	if sess != nil && strings.TrimSpace(sess.APIKey) != "" {
		return sess.APIKey, nil
	}
	return "", fmt.Errorf("API key not set (use --api-key, %s, or run create-api-key)", envAPIKey)
}

func resolveOCToken(explicit string) (string, error) {
	if v := strings.TrimSpace(explicit); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv(envOCToken)); v != "" {
		return v, nil
	}
	return getOpenShiftToken()
}

func getOpenShiftToken() (string, error) {
	out, err := exec.Command("oc", "whoami", "-t").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run `oc whoami -t`: %w", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", errors.New("`oc whoami -t` returned an empty token")
	}
	return token, nil
}

func detectClusterDomain() (string, error) {
	out, err := exec.Command("kubectl", "get", "ingresses.config.openshift.io", "cluster", "-o", "jsonpath={.spec.domain}").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run kubectl to detect cluster domain: %w", err)
	}
	domain := strings.TrimSpace(string(out))
	if domain == "" {
		return "", errors.New("kubectl returned an empty cluster domain")
	}
	return domain, nil
}

// ── helpers: HTTP ───────────────────────────────────────────────────────────

func doRequest(req *http.Request) ([]byte, error) {
	client := newHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed (%s): %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	return respBody, nil
}

func curlForRequest(req *http.Request, body []byte, stream bool) string {
	parts := []string{"curl", "-sSk"}
	if stream {
		parts = append(parts, "--no-buffer")
	}
	parts = append(parts,
		"-X", req.Method,
		quote(req.URL.String()),
	)

	headers := []string{"Authorization", "Content-Type", "X-MaaS-Subscription"}
	for _, name := range headers {
		if value := strings.TrimSpace(req.Header.Get(name)); value != "" {
			parts = append(parts, "-H", quote(name+": "+value))
		}
	}

	if len(body) > 0 {
		parts = append(parts, "-d", quote(string(body)))
	}

	return strings.Join(parts, " ")
}

func quote(s string) string {
	replacer := strings.NewReplacer("'", `'"'"'`)
	return "'" + replacer.Replace(s) + "'"
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func prettyPrintJSON(raw []byte) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Println(string(raw))
		return
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Println(string(raw))
		return
	}
	fmt.Println(string(out))
}

// ── session persistence ─────────────────────────────────────────────────────

func sessionFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".maas-cli", "session.json"), nil
}

func loadSession() (*session, error) {
	path, err := sessionFilePath()
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, nil
	}
	var sess session
	if err := json.Unmarshal(content, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func saveSession(sess *session) error {
	if sess == nil {
		return errors.New("nil session")
	}
	path, err := sessionFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}

// ── help ────────────────────────────────────────────────────────────────────

func printRootUsage() {
	fmt.Println(cliBanner)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  maas-cli <command> [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  endpoint          Detect MaaS API URL from cluster")
	fmt.Println("  create-api-key    Create an API key (POST /maas-api/v1/api-keys)")
	fmt.Println("  revoke-api-key    Revoke an API key (DELETE /maas-api/v1/api-keys/{id})")
	fmt.Println("  list-api-keys     Search/list API keys (POST /maas-api/v1/api-keys/search)")
	fmt.Println("  subscriptions     List accessible subscriptions (GET /v1/subscriptions)")
	fmt.Println("  models            List available models (GET /v1/models)")
	fmt.Println("  chat              Send a chat completion or start interactive chat")
	fmt.Println()
	fmt.Println("Quick Start:")
	fmt.Println("  1) maas-cli endpoint")
	fmt.Println("  2) maas-cli create-api-key --name my-key --expires-in 90d")
	fmt.Println("  3) maas-cli models")
	fmt.Println("  4) maas-cli chat --prompt 'Hello!'")
	fmt.Println("  5) maas-cli chat --interactive")
	fmt.Println()
	fmt.Println("Interactive chat commands: /quit, /clear, /history")
	fmt.Println()
	fmt.Printf("Environment: %s, %s, %s\n", envMaasAPIURL, envAPIKey, envOCToken)
	fmt.Println()
	fmt.Println("Use 'maas-cli <command> --help' for command-specific flags.")
}
