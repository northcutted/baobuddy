package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FileMode is a Unix permission mode. In JSON it may be an octal string ("0600", "0640") or a
// number. Numbers are taken literally, so 384 means 0600; Validate rejects a decimal 600 typo.
type FileMode uint32

// UnmarshalJSON accepts an octal string or a number.
func (m *FileMode) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(s), "0o"), 8, 32)
		if err != nil {
			return fmt.Errorf("file_mode %q isn't an octal mode such as \"0600\"", s)
		}
		*m = FileMode(v)
		return nil
	}
	var v uint32
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*m = FileMode(v)
	return nil
}

// Config defines the runtime configuration for baobuddy-receiver on a remote target host.
// It may hold OTLP auth headers: keep the file root-owned and readable only by the receiver's
// group (`root:granter 0640`).
type Config struct {
	// OpenBao / Vault server base URL (e.g. https://vault.example:8200).
	OpenBaoAddr string `json:"openbao_addr"`
	// Optional Vault Enterprise / OpenBao 2.x namespace (sent as X-Vault-Namespace).
	Namespace string `json:"namespace,omitempty"`
	// Optional PEM file of CA (or self-signed server) certificates that replace the system roots.
	CACertPath string `json:"ca_cert_path,omitempty"`
	// Directory where active grant files are stored. Must exist and be writable by the receiver.
	StateDir string `json:"state_dir"`
	// Path to the host's Ed25519 SSH public key returned by `pubkey` (optional).
	SSHPubKeyPath string `json:"ssh_pubkey_path,omitempty"`
	// Path where signed SSH user certificate is written (defaults to <StateDir>/ssh-cert.pub).
	SSHCertPath string `json:"ssh_cert_path,omitempty"`
	// Path where OpenBao token is written (defaults to <StateDir>/token).
	TokenPath string `json:"token_path,omitempty"`
	// Path where optional GitHub push token is written (defaults to <StateDir>/push-token).
	PushTokenPath string `json:"push_token_path,omitempty"`
	// Optional command executed by `tasks` to list active workloads (one per line).
	TasksCommand []string `json:"tasks_command,omitempty"`
	// Optional file group (GID) for grant files, for sharing with a workload user through 0640.
	// The receiver user must be a member of that group.
	FileOwnerGID int `json:"file_owner_gid,omitempty"`
	// File permission mode for grant files: "0600" (default) or "0640".
	FileMode FileMode `json:"file_mode,omitempty"`
	// Optional OpenTelemetry OTLP/HTTP endpoint (e.g. https://otel.corp.example:4318).
	OTLPEndpoint string `json:"otlp_endpoint,omitempty"`
	// Optional static HTTP headers for OTLP export (e.g. Authorization).
	OTLPHeaders map[string]string `json:"otlp_headers,omitempty"`
	// Logical service/host name reported in structured logs and OTLP telemetry.
	ServiceName string `json:"service_name,omitempty"`
	// Optional Prometheus textfile collector path (e.g. /var/lib/node_exporter/textfile/baobuddy.prom).
	MetricsFilePath string `json:"metrics_file_path,omitempty"`
	// Optional path to append structured JSON audit log lines.
	AuditLogPath string `json:"audit_log_path,omitempty"`
	// Maximum allowed grant TTL accepted from OpenBao lookup-self (seconds; default 86400 = 24h).
	MaxTTLSeconds int `json:"max_ttl_seconds,omitempty"`
	// If set, every policy on an installed token (other than "default") must be in this list.
	AllowedPolicies []string `json:"allowed_policies,omitempty"`
	// If set, an installed token's metadata must contain each of these key/value pairs, for
	// example {"on": "remote"} to accept only grants BaoBuddy minted for remote delivery.
	RequiredMeta map[string]string `json:"required_meta,omitempty"`
}

// Load reads and validates a JSON configuration file and applies safe defaults.
// Unknown keys are an error, so a typo can't silently fall back to a default.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ApplyDefaults populates derived paths and safe defaults.
func (c *Config) ApplyDefaults() {
	c.OpenBaoAddr = strings.TrimRight(strings.TrimSpace(c.OpenBaoAddr), "/")
	c.Namespace = strings.TrimSpace(c.Namespace)
	c.OTLPEndpoint = strings.TrimRight(strings.TrimSpace(c.OTLPEndpoint), "/")
	if c.StateDir == "" {
		c.StateDir = "/run/baobuddy"
	}
	if c.TokenPath == "" {
		c.TokenPath = filepath.Join(c.StateDir, "token")
	}
	if c.SSHCertPath == "" {
		c.SSHCertPath = filepath.Join(c.StateDir, "ssh-cert.pub")
	}
	if c.PushTokenPath == "" {
		c.PushTokenPath = filepath.Join(c.StateDir, "push-token")
	}
	if c.FileMode == 0 {
		c.FileMode = 0o600
	}
	if c.ServiceName == "" {
		c.ServiceName = "baobuddy-receiver"
	}
	if c.MaxTTLSeconds <= 0 {
		c.MaxTTLSeconds = 86400
	}
}

// Validate checks required fields and rejects unsafe configurations.
func (c *Config) Validate() error {
	if c.OpenBaoAddr == "" {
		return fmt.Errorf("openbao_addr is required")
	}
	if err := requireHTTPS("openbao_addr", c.OpenBaoAddr); err != nil {
		return err
	}
	if c.OTLPEndpoint != "" {
		if err := requireHTTPS("otlp_endpoint", c.OTLPEndpoint); err != nil {
			return err
		}
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return fmt.Errorf("state_dir must be an absolute path")
	}
	return c.FileMode.Validate()
}

// Validate limits shared credentials to read-only group access.
func (m FileMode) Validate() error {
	if m != 0o600 && m != 0o640 {
		return fmt.Errorf("file_mode %#o is not allowed; use \"0600\" or \"0640\" (as a quoted octal string)", uint32(m))
	}
	return nil
}

// requireHTTPS allows https://, and http:// only to a loopback host.
func requireHTTPS(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("%s must be a valid base URL", field)
	}
	if u.User != nil || u.ForceQuery || u.RawQuery != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%s must be a base URL without user information, a query, or a fragment", field)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%s must use https:// (plain http:// is allowed for loopback addresses only)", field)
}

// EndpointOrigin omits the reverse-proxy path and any credential-bearing URL components.
func EndpointOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "(invalid endpoint)"
	}
	return u.Scheme + "://" + u.Host
}
