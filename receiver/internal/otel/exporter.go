package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Event represents a non-secret BaoBuddy receiver audit event for SIEM / OTLP ingestion.
type Event struct {
	Action     string            `json:"action"`
	Outcome    string            `json:"outcome"`
	Namespace  string            `json:"namespace,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	Via        string            `json:"via,omitempty"`
	Policies   []string          `json:"policies,omitempty"`
	TTLSeconds int               `json:"ttl_seconds,omitempty"`
	Why        string            `json:"why,omitempty"`
	Error      string            `json:"error,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// Exporter emits zero-dependency OpenTelemetry OTLP/HTTP JSON logs + metrics,
// optional JSON audit log lines, and optional Prometheus textfile metrics.
type Exporter struct {
	Endpoint        string
	Headers         map[string]string
	ServiceName     string
	HostName        string
	AuditLogPath    string
	MetricsFilePath string
	HTTPClient      *http.Client
}

// NewExporter builds an Exporter with safe short timeouts so telemetry never blocks grants.
func NewExporter(endpoint string, headers map[string]string, serviceName, auditLogPath, metricsFilePath string) *Exporter {
	host, _ := os.Hostname()
	if serviceName == "" {
		serviceName = "baobuddy-receiver"
	}
	return &Exporter{
		Endpoint:        strings.TrimRight(strings.TrimSpace(endpoint), "/"),
		Headers:         headers,
		ServiceName:     serviceName,
		HostName:        host,
		AuditLogPath:    strings.TrimSpace(auditLogPath),
		MetricsFilePath: strings.TrimSpace(metricsFilePath),
		HTTPClient: &http.Client{
			Timeout: 2 * time.Second,
			// Never follow redirects: they could carry otlp_headers (e.g. Authorization) elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Emit sends the event to all configured sinks (JSON audit file + OTLP/HTTP logs & metrics).
// Errors are returned only for diagnostics; callers may log and proceed. OTLP export has its own
// short deadline, so a slow collector can't use up the caller's time budget.
func (e *Exporter) Emit(ctx context.Context, ev Event) error {
	now := time.Now().UTC()
	var failures []error
	if len(ev.Error) > 300 {
		ev.Error = ev.Error[:300] + "…"
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()

	if e.AuditLogPath != "" {
		if err := e.appendAuditLine(now, ev); err != nil {
			failures = append(failures, errors.New("could not append to the configured audit log"))
		}
	}

	if e.Endpoint != "" {
		if err := e.postOTLPLog(ctx, now, ev); err != nil {
			failures = append(failures, errors.New("OTLP log delivery failed"))
		}
		if err := e.postOTLPMetric(ctx, now, ev); err != nil {
			failures = append(failures, errors.New("OTLP metric delivery failed"))
		}
	}
	return errors.Join(failures...)
}

// WritePrometheusState writes a Prometheus node_exporter textfile gauge snapshot of active grant state.
func (e *Exporter) WritePrometheusState(active bool, ttlSeconds int, sshActive bool, pushActive bool) error {
	if e.MetricsFilePath == "" {
		return nil
	}
	activeVal := 0
	if active {
		activeVal = 1
	}
	sshVal := 0
	if sshActive {
		sshVal = 1
	}
	pushVal := 0
	if pushActive {
		pushVal = 1
	}
	if ttlSeconds < 0 {
		ttlSeconds = 0
	}
	content := fmt.Sprintf(
		"# HELP baobuddy_receiver_grant_active Whether an OpenBao grant token is currently active (1 or 0).\n"+
			"# TYPE baobuddy_receiver_grant_active gauge\n"+
			"baobuddy_receiver_grant_active %d\n"+
			"# HELP baobuddy_receiver_grant_ttl_seconds Remaining TTL of the active OpenBao grant in seconds.\n"+
			"# TYPE baobuddy_receiver_grant_ttl_seconds gauge\n"+
			"baobuddy_receiver_grant_ttl_seconds %d\n"+
			"# HELP baobuddy_receiver_ssh_cert_active Whether an ephemeral SSH user certificate is active (1 or 0).\n"+
			"# TYPE baobuddy_receiver_ssh_cert_active gauge\n"+
			"baobuddy_receiver_ssh_cert_active %d\n"+
			"# HELP baobuddy_receiver_push_token_active Whether an ephemeral Git push token is active (1 or 0).\n"+
			"# TYPE baobuddy_receiver_push_token_active gauge\n"+
			"baobuddy_receiver_push_token_active %d\n",
		activeVal, ttlSeconds, sshVal, pushVal,
	)
	// A unique O_EXCL temp file: a fixed name could be a symlink planted in a shared
	// textfile-collector directory.
	tmp, err := os.CreateTemp(filepath.Dir(e.MetricsFilePath), ".baobuddy-prom-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err = tmp.Chmod(0o644); err == nil {
		_, err = tmp.WriteString(content)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmpPath, e.MetricsFilePath)
	}
	if err != nil {
		_ = os.Remove(tmpPath)
	}
	return err
}

func (e *Exporter) appendAuditLine(now time.Time, ev Event) error {
	record := map[string]any{
		"timestamp":   now.Format(time.RFC3339Nano),
		"service":     e.ServiceName,
		"host":        e.HostName,
		"action":      ev.Action,
		"outcome":     ev.Outcome,
		"namespace":   ev.Namespace,
		"actor":       ev.Actor,
		"via":         ev.Via,
		"policies":    ev.Policies,
		"ttl_seconds": ev.TTLSeconds,
		"why":         ev.Why,
		"error":       ev.Error,
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := e.openAuditLog()
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return errors.Join(err, f.Close())
}

func (e *Exporter) openAuditLog() (*os.File, error) {
	f, err := os.OpenFile(e.AuditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o640)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("audit destination must be a regular file")
	}
	return f, nil
}

// CheckLocalSinks checks access without writing an event or replacing existing metrics.
func (e *Exporter) CheckLocalSinks() error {
	var failures []error
	if e.AuditLogPath != "" {
		f, err := e.openAuditLog()
		if err != nil || f.Close() != nil {
			failures = append(failures, errors.New("cannot open audit_log_path for append"))
		}
	}
	if e.MetricsFilePath != "" {
		fi, err := os.Lstat(e.MetricsFilePath)
		if (err != nil && !os.IsNotExist(err)) || (err == nil && !fi.Mode().IsRegular()) {
			failures = append(failures, errors.New("invalid metrics_file_path destination"))
		} else {
			f, err := os.CreateTemp(filepath.Dir(e.MetricsFilePath), ".baobuddy-prom-probe-*")
			if err == nil {
				err = errors.Join(f.Close(), os.Remove(f.Name()))
			}
			if err != nil {
				failures = append(failures, errors.New("metrics_file_path directory is not writable"))
			}
		}
	}
	return errors.Join(failures...)
}

func (e *Exporter) postOTLPLog(ctx context.Context, now time.Time, ev Event) error {
	attrs := e.eventAttributes(ev)
	severity := 9 // INFO
	severityText := "INFO"
	if ev.Outcome != "ok" {
		severity = 17 // ERROR
		severityText = "ERROR"
	}
	payload := map[string]any{
		"resourceLogs": []any{
			map[string]any{
				"resource": map[string]any{
					"attributes": e.resourceAttributes(),
				},
				"scopeLogs": []any{
					map[string]any{
						"scope": map[string]any{"name": "baobuddy.receiver", "version": "0.1.0"},
						"logRecords": []any{
							map[string]any{
								"timeUnixNano":   strconv.FormatInt(now.UnixNano(), 10),
								"severityNumber": severity,
								"severityText":   severityText,
								"body": map[string]any{
									"stringValue": fmt.Sprintf("baobuddy receiver %s: %s", ev.Action, ev.Outcome),
								},
								"attributes": attrs,
							},
						},
					},
				},
			},
		},
	}
	return e.postJSON(ctx, e.Endpoint+"/v1/logs", payload)
}

func (e *Exporter) postOTLPMetric(ctx context.Context, now time.Time, ev Event) error {
	nowNano := strconv.FormatInt(now.UnixNano(), 10)
	payload := map[string]any{
		"resourceMetrics": []any{
			map[string]any{
				"resource": map[string]any{
					"attributes": e.resourceAttributes(),
				},
				"scopeMetrics": []any{
					map[string]any{
						"scope": map[string]any{"name": "baobuddy.receiver", "version": "0.1.0"},
						"metrics": []any{
							map[string]any{
								"name":        "baobuddy.receiver.events",
								"description": "Count of BaoBuddy receiver grant lifecycle operations",
								"unit":        "1",
								"sum": map[string]any{
									"isMonotonic":            true,
									"aggregationTemporality": 1, // DELTA
									"dataPoints": []any{
										map[string]any{
											"startTimeUnixNano": nowNano,
											"timeUnixNano":      nowNano,
											"asInt":             "1",
											"attributes": []any{
												kvString("baobuddy.action", ev.Action),
												kvString("baobuddy.outcome", ev.Outcome),
												kvString("baobuddy.namespace", ev.Namespace),
												kvString("baobuddy.via", ev.Via),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return e.postJSON(ctx, e.Endpoint+"/v1/metrics", payload)
}

func (e *Exporter) postJSON(ctx context.Context, url string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}
	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp %s returned HTTP %d", url, resp.StatusCode)
	}
	return nil
}

func (e *Exporter) resourceAttributes() []any {
	return []any{
		kvString("service.name", e.ServiceName),
		kvString("host.name", e.HostName),
	}
}

func (e *Exporter) eventAttributes(ev Event) []any {
	attrs := []any{
		kvString("baobuddy.action", ev.Action),
		kvString("baobuddy.outcome", ev.Outcome),
	}
	if ev.Namespace != "" {
		attrs = append(attrs, kvString("baobuddy.namespace", ev.Namespace))
	}
	if ev.Actor != "" {
		attrs = append(attrs, kvString("enduser.id", ev.Actor))
	}
	if ev.Via != "" {
		attrs = append(attrs, kvString("baobuddy.via", ev.Via))
	}
	if len(ev.Policies) > 0 {
		attrs = append(attrs, kvString("baobuddy.policies", strings.Join(ev.Policies, ",")))
	}
	if ev.TTLSeconds > 0 {
		attrs = append(attrs, map[string]any{
			"key":   "baobuddy.ttl_seconds",
			"value": map[string]any{"intValue": strconv.Itoa(ev.TTLSeconds)},
		})
	}
	if ev.Why != "" {
		attrs = append(attrs, kvString("baobuddy.why", ev.Why))
	}
	if ev.Error != "" {
		attrs = append(attrs, kvString("error.message", ev.Error))
	}
	for k, v := range ev.Extra {
		attrs = append(attrs, kvString("baobuddy."+k, v))
	}
	return attrs
}

func kvString(k, v string) map[string]any {
	return map[string]any{
		"key":   k,
		"value": map[string]any{"stringValue": v},
	}
}
