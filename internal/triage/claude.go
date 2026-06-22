package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Claude Messages API constants. The default model is the latest Opus; the
// endpoint is overridable so a test (or an on-prem proxy) can point elsewhere.
const (
	defaultModel     = "claude-opus-4-8"
	defaultEndpoint  = "https://api.anthropic.com"
	defaultMaxTokens = 1024
	anthropicVersion = "2023-06-01"
	requestTimeout   = 30 * time.Second
)

// claudeSummarizer asks the Claude Messages API for a triage report over raw HTTP
// — no SDK, so ARGUS keeps its dependency-free, offline-buildable posture. It
// returns an error (not a partial report) on any failure so the fallback wrapper
// can substitute the deterministic template summary.
type claudeSummarizer struct {
	httpClient *http.Client
	endpoint   string
	apiKey     string
	model      string
	maxTokens  int
}

func newClaudeSummarizer(cfg Config) *claudeSummarizer {
	return &claudeSummarizer{
		httpClient: &http.Client{Timeout: requestTimeout},
		endpoint:   orDefault(cfg.Endpoint, defaultEndpoint),
		apiKey:     cfg.APIKey,
		model:      orDefault(cfg.Model, defaultModel),
		maxTokens:  orDefaultInt(cfg.MaxTokens, defaultMaxTokens),
	}
}

type messagesRequest struct {
	Model     string       `json:"model"`
	MaxTokens int          `json:"max_tokens"`
	System    string       `json:"system,omitempty"`
	Messages  []apiMessage `json:"messages"`
}

type apiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

const triageSystemPrompt = `You are a SOC analyst assistant for the ARGUS EDR. Given a structured ` +
	`security incident, produce a concise triage report. Respond with ONLY a JSON object: ` +
	`{"summary": string, "severity": "low|medium|high|critical", "containment": [string], "rule_draft": string}. ` +
	`rule_draft is an optional ARGUS/YARA rule sketch; use "" when none applies. Output no text outside the JSON.`

func (c *claudeSummarizer) Summarize(ctx context.Context, incident Incident) (Report, error) {
	body, err := json.Marshal(messagesRequest{
		Model:     c.model,
		MaxTokens: c.maxTokens,
		System:    triageSystemPrompt,
		Messages:  []apiMessage{{Role: "user", Content: renderIncident(incident)}},
	})
	if err != nil {
		return Report{}, fmt.Errorf("marshal triage request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return Report{}, fmt.Errorf("build triage request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Report{}, fmt.Errorf("call triage api: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Report{}, fmt.Errorf("read triage response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Report{}, fmt.Errorf("triage api status %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	return parseReport(payload)
}

// parseReport extracts the Report from a Messages API response, treating a refusal
// or a non-JSON body as an error so the caller falls back to the template. (Opus
// safety classifiers can refuse security-tooling prompts — handle it, don't crash.)
func parseReport(payload []byte) (Report, error) {
	var response messagesResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return Report{}, fmt.Errorf("decode triage response: %w", err)
	}
	if response.StopReason == "refusal" {
		return Report{}, fmt.Errorf("triage api refused the request")
	}
	text := firstText(response.Content)
	if text == "" {
		return Report{}, fmt.Errorf("triage api returned no text")
	}
	var report Report
	if err := json.Unmarshal([]byte(text), &report); err != nil {
		return Report{}, fmt.Errorf("parse triage report json: %w", err)
	}
	report.Source = ProviderClaude
	return report, nil
}

func firstText(blocks []contentBlock) string {
	for _, block := range blocks {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			return block.Text
		}
	}
	return ""
}

// renderIncident formats the incident as the user message — compact, labelled,
// and free of any host-identifying noise beyond what the alert already carries.
func renderIncident(incident Incident) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Incident %s on host %s\n", orUnknown(incident.ID), orUnknown(incident.Hostname))
	fmt.Fprintf(&builder, "Process: %s (pid %d)\nRisk score: %d (%s)\n",
		orUnknown(incident.ProcessName), incident.PID, incident.RiskScore, SeverityForRisk(incident.RiskScore))
	if tactics := sortedTactics(incident.Techniques); len(tactics) > 0 {
		fmt.Fprintf(&builder, "Tactics: %s\n", strings.Join(tactics, ", "))
	}
	builder.WriteString("Techniques:\n")
	for _, technique := range incident.Techniques {
		fmt.Fprintf(&builder, "  - %s %s (%s)\n", technique.ID, technique.Name, technique.Tactic)
	}
	builder.WriteString("Alerts:\n")
	for _, alert := range incident.Alerts {
		fmt.Fprintf(&builder, "  - [%s] %s %s (%s)\n", alert.Severity, alert.RuleID, alert.RuleName, alert.Technique)
	}
	return builder.String()
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func orDefaultInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}
