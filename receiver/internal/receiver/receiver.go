package receiver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/config"
	"github.com/northcutted/baobuddy/receiver/internal/openbao"
	"github.com/northcutted/baobuddy/receiver/internal/otel"
)

const (
	maxPayloadBytes       = 256 * 1024
	maxArtifactBytes      = 64 * 1024
	maxArtifacts          = 16
	maxTokenFileBytes     = 4 * 1024
	maxSecondaryFileBytes = maxPayloadBytes // Status must accept every certificate Install can deliver.
	maxStateFileBytes     = 64 * 1024
	lockFileName          = ".lock"
	stateFileName         = ".grant.json"
	artifactsDirName      = "artifacts"
)

// Artifact represents a workflow-agnostic named credential file delivered alongside a grant.
type Artifact struct {
	Name      string `json:"name"`
	Content   string `json:"content"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// InstallPayloadV2 is the JSON envelope accepted by `install` for delivering arbitrary extension artifacts.
type InstallPayloadV2 struct {
	Version   int        `json:"version"`
	Token     string     `json:"token"`
	SSHCert   string     `json:"ssh_cert,omitempty"`
	PushToken string     `json:"push_token,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

// grantState records expiry times so `cleanup` can delete files whose contents the receiver
// can't inspect (SSH certificates, artifacts) once they expire, and records a hash of a token
// whose remote revocation/invalidation was already confirmed so a failed local cleanup can be
// retried safely for that same grant.
type grantState struct {
	Parents            deliveryParents  `json:"delivery_parents,omitzero"`
	TokenExpiresAt     int64            `json:"token_expires_at"`
	ArtifactExpiresAt  map[string]int64 `json:"artifact_expires_at,omitempty"`
	RevokedTokenSHA256 string           `json:"revoked_token_sha256,omitempty"`
}

// OpenBaoClient abstracts OpenBao token verification & revocation for easy unit testing.
// LookupSelf and RevokeSelf return an error wrapping openbao.ErrInvalidToken when OpenBao
// definitively rejects the token; any other error means its state is unknown.
type OpenBaoClient interface {
	CheckHealth(ctx context.Context) (version string, sealed bool, err error)
	LookupSelf(ctx context.Context, token string) (openbao.TokenInfo, error)
	RevokeSelf(ctx context.Context, token string) error
}

// Receiver implements the BaoBuddy forced-command SSH receiver protocol:
// `install`, `status`, `revoke`, `pubkey`, `tasks`, `cleanup`, and `doctor`.
type Receiver struct {
	Cfg      config.Config
	Client   OpenBaoClient
	Exporter *otel.Exporter
	Warn     func(string)
	Now      func() time.Time
}

// New builds a Receiver from validated Config.
func New(cfg config.Config, client OpenBaoClient, exporter *otel.Exporter) *Receiver {
	return &Receiver{
		Cfg:      cfg,
		Client:   client,
		Exporter: exporter,
		Now:      time.Now,
		Warn:     func(msg string) { fmt.Fprintln(os.Stderr, "Warning:", msg) },
	}
}

// Install reads either:
//   - v1 3-line stdin (`<token>\n<sshCert>\n<pushToken>\n`), or
//   - v2 JSON envelope (`{"version":2,"token":"...","artifacts":[...]}`)
//
// It verifies the token against OpenBao, writes every file, and only then installs the token and
// revokes the one it replaces. A pre-commit failure rolls back the prior grant,
// retaining the journal for retry if a destination is still unavailable.
func (r *Receiver) Install(ctx context.Context, stdin io.Reader) (string, error) {
	rawInput, err := io.ReadAll(io.LimitReader(stdin, maxPayloadBytes+1))
	if err != nil {
		return "", fmt.Errorf("read install payload: %w", err)
	}
	if len(rawInput) > maxPayloadBytes {
		return "", r.reject(ctx, "payload too large", fmt.Sprintf("install payload exceeds %d bytes", maxPayloadBytes))
	}

	var token, sshCert, pushToken string
	var artifacts []Artifact
	trimmed := bytes.TrimSpace(rawInput)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var payload InstallPayloadV2
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&payload); err != nil {
			return "", r.reject(ctx, "invalid v2 JSON payload", "invalid JSON install payload")
		}
		if payload.Version != 2 {
			return "", r.reject(ctx, "unsupported payload version", fmt.Sprintf("unsupported install payload version %d", payload.Version))
		}
		token = strings.TrimSpace(payload.Token)
		sshCert = strings.TrimSpace(payload.SSHCert)
		pushToken = strings.TrimSpace(payload.PushToken)
		artifacts = payload.Artifacts
		if err := r.validateArtifacts(ctx, artifacts); err != nil {
			return "", err
		}
	} else {
		reader := bufio.NewReader(bytes.NewReader(rawInput))
		token, _ = readLineTrimmed(reader)
		sshCert, _ = readLineTrimmed(reader)
		pushToken, _ = readLineTrimmed(reader)
	}

	if !isValidToken(token) {
		return "", r.reject(ctx, "invalid token format", "invalid OpenBao token format")
	}
	if sshCert != "" && (!strings.HasPrefix(sshCert, "ssh-ed25519-cert-v01@openssh.com ") || strings.ContainsAny(sshCert, "\r\n")) {
		return "", r.reject(ctx, "invalid SSH certificate format", "invalid SSH certificate format")
	}
	if pushToken != "" && !isValidPushTokenLine(pushToken) {
		return "", r.reject(ctx, "invalid push token format", "invalid push token format (expected '<epoch> <token>')")
	}

	info, err := r.Client.LookupSelf(ctx, token)
	if err != nil {
		return "", r.reject(ctx, err.Error(), fmt.Sprintf("OpenBao didn't accept the token: %v", err))
	}
	if err := r.checkToken(info); err != nil {
		return "", r.reject(ctx, err.Error(), err.Error())
	}

	unlock, err := r.lock(ctx, nil)
	if err != nil {
		return "", err
	}
	defer unlock()

	now := r.Now()
	tokenExpiry := now.Add(time.Duration(info.TTLSeconds) * time.Second).Unix()
	state, stateExists, err := r.readState()
	if err != nil {
		return "", fmt.Errorf("read previous grant state: %w", err)
	}
	if err := errors.Join(state.Parents.SSH.check(r.Cfg.SSHCertPath), state.Parents.Push.check(r.Cfg.PushTokenPath)); err != nil {
		return "", fmt.Errorf("install did not commit: %w", err)
	}
	oldToken, tokenExists, err := (grantFiles{Receiver: r, parents: state.Parents}).token()
	if err != nil {
		return "", fmt.Errorf("read previous grant: %w", err)
	}
	if !tokenExists && stateExists {
		return "", errors.New("previous grant state exists but its token is missing; inspect the delivery path and run cleanup before installing")
	}

	cleanupErr, err := r.writeGrantFiles(token, sshCert, pushToken, artifacts, tokenExpiry)
	if err != nil {
		r.emit(ctx, otel.Event{Action: "install", Outcome: "failed", Error: err.Error()})
		return "", fmt.Errorf("install did not commit: %w", err)
	}

	policies := filterDefaultPolicy(info.Policies)
	message := fmt.Sprintf("Granted until %s (%s)", time.Unix(tokenExpiry, 0).UTC().Format(time.RFC3339), strings.Join(policies, ", "))

	if cleanupErr != nil {
		message += fmt.Sprintf(". Warning: committed grant; local transaction cleanup requires retry (%v)", cleanupErr)
	}

	if oldToken != "" && oldToken != token {
		if err := r.Client.RevokeSelf(ctx, oldToken); err != nil && !errors.Is(err, openbao.ErrInvalidToken) {
			r.emit(ctx, otel.Event{Action: "revoke_previous", Outcome: "failed", Error: err.Error()})
			message += fmt.Sprintf(". Warning: the previous grant could not be revoked at OpenBao (%v); it stays valid until it expires", err)
		}
	}

	r.emit(ctx, otel.Event{
		Action:     "install",
		Outcome:    "ok",
		Namespace:  r.Cfg.Namespace,
		Actor:      info.Meta["by"],
		Via:        info.Meta["via"],
		Policies:   policies,
		TTLSeconds: info.TTLSeconds,
		Why:        info.Meta["why"],
	})
	r.writeProm(true, info.TTLSeconds, sshCert != "", pushToken != "")
	return message, nil
}

// checkToken enforces the receiver's acceptance rules on OpenBao's own view of the token.
func (r *Receiver) checkToken(info openbao.TokenInfo) error {
	switch {
	case info.TTLSeconds <= 0:
		return fmt.Errorf("token has no remaining TTL")
	case info.TTLSeconds > r.Cfg.MaxTTLSeconds:
		return fmt.Errorf("token TTL %ds exceeds receiver limit %ds", info.TTLSeconds, r.Cfg.MaxTTLSeconds)
	case info.Renewable:
		return fmt.Errorf("grant token must not be renewable")
	case !info.Orphan:
		return fmt.Errorf("grant token must be an orphan")
	case info.Type == "batch":
		return fmt.Errorf("batch tokens can't be revoked individually and are refused")
	}
	if len(r.Cfg.AllowedPolicies) > 0 {
		if info.Policies == nil {
			return errors.New("OpenBao did not report the token policies")
		}
		for _, policies := range info.ExternalNamespacePolicies {
			if len(policies) > 0 {
				return errors.New("token carries policies outside this receiver's namespace")
			}
		}
		for _, p := range slices.Concat(info.Policies, info.IdentityPolicies) {
			if p != "default" && !slices.Contains(r.Cfg.AllowedPolicies, p) {
				return fmt.Errorf("policy %q isn't in this receiver's allowed_policies", p)
			}
		}
	}
	for key, want := range r.Cfg.RequiredMeta {
		if info.Meta[key] != want {
			return fmt.Errorf("token metadata %q must be %q", key, want)
		}
	}
	return nil
}

func (r *Receiver) validateArtifacts(ctx context.Context, artifacts []Artifact) error {
	if len(artifacts) > maxArtifacts {
		return r.reject(ctx, "too many artifacts", fmt.Sprintf("too many artifacts (%d, max %d)", len(artifacts), maxArtifacts))
	}
	seen := map[string]bool{}
	for _, a := range artifacts {
		if !isSafeArtifactName(a.Name) {
			return r.reject(ctx, "invalid artifact name", fmt.Sprintf("unsafe artifact filename %q", a.Name))
		}
		if seen[a.Name] {
			return r.reject(ctx, "duplicate artifact name", fmt.Sprintf("duplicate artifact filename %q", a.Name))
		}
		seen[a.Name] = true
		if len(a.Content) > maxArtifactBytes {
			return r.reject(ctx, "artifact too large", fmt.Sprintf("artifact %q exceeds %d bytes", a.Name, maxArtifactBytes))
		}
		if a.ExpiresAt < 0 {
			return r.reject(ctx, "invalid artifact expiry", fmt.Sprintf("artifact %q has a negative expires_at", a.Name))
		}
	}
	return nil
}

// Status reports active grant, SSH certificate, and push token state in canonical BaoBuddy lines.
// Files are deleted only when OpenBao definitively rejects the token, its recorded expiry has
// passed, or the token file is genuinely absent (ENOENT). Unreadable, malformed, empty, or
// non-regular files never authorize destructive cleanup and return an error.
func (r *Receiver) Status(ctx context.Context) (string, error) {
	var backupErr error
	unlock, err := r.lock(ctx, &backupErr)
	if err != nil {
		return "", err
	}
	defer unlock()

	now := r.Now()
	state, stateExists, stateErr := r.readState()
	files := grantFiles{r, state.Parents, backupErr}
	token, tokenExists, tokenErr := files.token()

	var lines []string
	var localErrs []error
	upstreamOutcome := ""
	tokenActive := false
	ttlSeconds := 0
	allowArtifactSweep := false
	allowPushSweep := (tokenErr == nil && stateErr == nil)

	switch {
	case tokenErr != nil:
		// Unreadable, malformed, empty, or non-regular token file: never delete anything.
		tokenActive = true
		localErrs = append(localErrs, tokenErr)
		if stateErr != nil {
			localErrs = append(localErrs, stateErr)
		}
		lines = append(lines, fmt.Sprintf("Secrets: unknown (local token error: %v)", tokenErr))

	case !tokenExists:
		// Genuine ENOENT on token file: only clean up leftovers if state file is absent or valid.
		if stateErr != nil {
			localErrs = append(localErrs, stateErr)
			lines = append(lines, fmt.Sprintf("Secrets: unknown (local state error: %v)", stateErr))
		} else {
			if rmErr := files.removeSecondaryFiles(); rmErr != nil {
				if stateExists && state.RevokedTokenSHA256 != "" {
					upstreamOutcome = "grant was already confirmed revoked at OpenBao"
				}
				localErrs = append(localErrs, rmErr)
				lines = append(lines, fmt.Sprintf("Secrets: unknown (local cleanup failed: %v)", rmErr))
			} else {
				state = grantState{}
				lines = append(lines, "Secrets: no grant")
			}
		}

	case stateErr == nil && stateExists && state.RevokedTokenSHA256 != "" && state.RevokedTokenSHA256 == tokenDigest(token):
		// Same-grant retry: remote revocation/invalidation was already confirmed for this exact token.
		if rmErr := files.removeAllGrantFiles(); rmErr != nil {
			tokenActive = true
			upstreamOutcome = "grant was already confirmed revoked at OpenBao"
			localErrs = append(localErrs, rmErr)
			lines = append(lines, fmt.Sprintf("Secrets: unknown (revoked at OpenBao, but local cleanup failed: %v)", rmErr))
		} else {
			state = grantState{}
			lines = append(lines, "Secrets: no grant")
		}

	default:
		stateMatchesToken := stateErr == nil && stateExists && (state.RevokedTokenSHA256 == "" || state.RevokedTokenSHA256 == tokenDigest(token))
		info, lookupErr := r.Client.LookupSelf(ctx, token)
		switch {
		case lookupErr == nil && info.TTLSeconds > 0:
			tokenActive = true
			ttlSeconds = info.TTLSeconds
			allowArtifactSweep = stateMatchesToken
			policies := filterDefaultPolicy(info.Policies)
			detail := fmt.Sprintf("active (%s left; %s)", formatDuration(info.TTLSeconds), strings.Join(policies, ", "))
			if why := strings.TrimSpace(info.Meta["why"]); why != "" && why != "none given" {
				detail += " — " + why
			}
			lines = append(lines, "Secrets: "+detail)
			if stateErr != nil {
				localErrs = append(localErrs, stateErr)
			}

		case errors.Is(lookupErr, openbao.ErrInvalidToken) ||
			(stateMatchesToken && state.TokenExpiresAt > 0 && now.Unix() >= state.TokenExpiresAt):
			confirmedByOpenBao := errors.Is(lookupErr, openbao.ErrInvalidToken)
			if confirmedByOpenBao {
				upstreamOutcome = "OpenBao confirmed token is invalid or revoked"
			} else {
				upstreamOutcome = "recorded grant expiry elapsed (OpenBao did not confirm revocation)"
			}
			cleanupErr := stateErr
			if confirmedByOpenBao && cleanupErr == nil {
				// Keep the token for a retry if the confirmation cannot be stored.
				cleanupErr = r.recordRemoteConfirmation(state, token)
			}
			if cleanupErr == nil {
				cleanupErr = files.removeAllGrantFiles()
			}
			if cleanupErr != nil {
				localErrs = append(localErrs, cleanupErr)
				lines = append(lines, fmt.Sprintf("Secrets: unknown (%s, but local cleanup failed: %v)", upstreamOutcome, cleanupErr))
			} else {
				state = grantState{}
				lines = append(lines, "Secrets: no grant")
			}

		default:
			tokenActive = true
			allowArtifactSweep = stateMatchesToken
			if lookupErr == nil {
				lines = append(lines, "Secrets: unknown (OpenBao returned ambiguous TTL 0)")
			} else {
				lines = append(lines, fmt.Sprintf("Secrets: unknown (couldn't check with OpenBao: %v)", lookupErr))
			}
			if stateErr != nil {
				localErrs = append(localErrs, stateErr)
			}
		}
	}

	if allowArtifactSweep {
		if sweepErr := r.sweepExpiredArtifacts(state, now); sweepErr != nil {
			localErrs = append(localErrs, sweepErr)
		}
	}

	sshActive := false
	cert, certExists, certErr := state.Parents.SSH.readSecondary(r.Cfg.SSHCertPath)
	switch {
	case certErr != nil:
		localErrs = append(localErrs, certErr)
		lines = append(lines, fmt.Sprintf("SSH: unknown (local certificate error: %v)", certErr))
	case !certExists:
		lines = append(lines, "SSH: no certificate")
	case cert == "" || !strings.HasPrefix(cert, "ssh-ed25519-cert-v01@openssh.com ") || strings.ContainsAny(cert, "\r\n"):
		localErrs = append(localErrs, fmt.Errorf("ssh certificate file %s is empty or malformed", filepath.Base(r.Cfg.SSHCertPath)))
		lines = append(lines, "SSH: unknown (malformed certificate file)")
	default:
		sshActive = true
		lines = append(lines, "SSH: certificate present")
	}

	pushActive := false
	pushLine, pushExists, pushErr := state.Parents.Push.readSecondary(r.Cfg.PushTokenPath)
	switch {
	case pushErr != nil:
		localErrs = append(localErrs, pushErr)
		lines = append(lines, fmt.Sprintf("Push: unknown (local push token error: %v)", pushErr))
	case !pushExists:
		lines = append(lines, "Push: no token")
	case pushLine == "" || !isValidPushTokenLine(pushLine):
		localErrs = append(localErrs, fmt.Errorf("push token file %s is empty or malformed", filepath.Base(r.Cfg.PushTokenPath)))
		lines = append(lines, "Push: unknown (malformed push token file)")
	default:
		if remaining, ok := pushTokenRemaining(pushLine, now); ok && remaining > 0 {
			pushActive = true
			lines = append(lines, fmt.Sprintf("Push: active (%s left)", formatDuration(remaining)))
		} else if ok {
			if !allowPushSweep {
				lines = append(lines, "Push: expired (retained due to local token/state error)")
			} else if rmErr := state.Parents.Push.remove(r.Cfg.PushTokenPath); rmErr != nil {
				localErrs = append(localErrs, rmErr)
				lines = append(lines, fmt.Sprintf("Push: unknown (expired, but local cleanup failed: %v)", rmErr))
			} else {
				lines = append(lines, "Push: no token")
			}
		} else {
			localErrs = append(localErrs, fmt.Errorf("push token file %s has unparseable expiry", filepath.Base(r.Cfg.PushTokenPath)))
			lines = append(lines, "Push: unknown (malformed push token file)")
		}
	}

	r.writeProm(tokenActive, ttlSeconds, sshActive, pushActive)
	statusText := strings.Join(lines, "\n")
	if backupErr != nil && !errors.Is(errors.Join(localErrs...), backupErr) {
		localErrs = append(localErrs, backupErr)
	}
	if len(localErrs) > 0 {
		combined := errors.Join(localErrs...)
		if upstreamOutcome != "" {
			return statusText, fmt.Errorf("upstream: %s; local cleanup failed: %w", upstreamOutcome, combined)
		}
		return statusText, fmt.Errorf("local grant I/O error: %w", combined)
	}
	return statusText, nil
}

// Revoke revokes the token at OpenBao and deletes the local grant files. If OpenBao can't confirm
// the revocation, the token file and `.grant.json` are kept so revoke can be retried, and an error
// is returned. Unreadable, malformed, empty, or non-regular local files never authorize destructive
// cleanup. If upstream revocation succeeds but local file deletion fails, retry state is retained
// and both outcomes are reported separately.
func (r *Receiver) Revoke(ctx context.Context) (string, error) {
	var backupErr error
	unlock, err := r.lock(ctx, &backupErr)
	if err != nil {
		return "", err
	}
	defer unlock()

	state, stateExists, stateErr := r.readState()
	files := grantFiles{r, state.Parents, backupErr}
	token, tokenExists, tokenErr := files.token()

	if tokenErr != nil {
		combined := errors.Join(tokenErr, stateErr)
		r.emit(ctx, otel.Event{Action: "revoke", Outcome: "failed", Namespace: r.Cfg.Namespace, Error: combined.Error()})
		return "", fmt.Errorf("local token file error (%v); nothing was revoked at OpenBao or deleted locally", combined)
	}

	if !tokenExists {
		if stateErr != nil {
			r.emit(ctx, otel.Event{Action: "revoke", Outcome: "failed", Namespace: r.Cfg.Namespace, Error: stateErr.Error()})
			return "", fmt.Errorf("token file is absent, but local grant state could not be read (%v); leftover files were not deleted", stateErr)
		}
		if rmErr := files.removeSecondaryFiles(); rmErr != nil {
			r.emit(ctx, otel.Event{Action: "revoke", Outcome: "failed", Namespace: r.Cfg.Namespace, Error: rmErr.Error()})
			if stateExists && state.RevokedTokenSHA256 != "" {
				return "", fmt.Errorf("upstream: grant was already confirmed revoked at OpenBao; local cleanup failed (%v); retry state was kept", rmErr)
			}
			return "", fmt.Errorf("upstream: no grant token was installed; local cleanup failed (%v); retry state was kept", rmErr)
		}
		if stateExists && state.RevokedTokenSHA256 != "" {
			r.emit(ctx, otel.Event{Action: "revoke", Outcome: "ok", Namespace: r.Cfg.Namespace})
			r.writeProm(false, 0, false, false)
			return "Revoked the grant at OpenBao and removed local credentials.", nil
		}
		r.emit(ctx, otel.Event{Action: "revoke", Outcome: "no_grant", Namespace: r.Cfg.Namespace})
		r.writeProm(false, 0, false, false)
		return "No grant was installed. Removed any leftover local files.", nil
	}

	// Same-grant retry when remote revocation/invalidation was already confirmed on a prior run.
	if stateErr == nil && stateExists && state.RevokedTokenSHA256 != "" && state.RevokedTokenSHA256 == tokenDigest(token) {
		if rmErr := files.removeAllGrantFiles(); rmErr != nil {
			r.emit(ctx, otel.Event{Action: "revoke", Outcome: "failed", Namespace: r.Cfg.Namespace, Error: rmErr.Error()})
			return "", fmt.Errorf("upstream: grant was already confirmed revoked at OpenBao; local cleanup failed (%v); retry state was kept", rmErr)
		}
		r.emit(ctx, otel.Event{Action: "revoke", Outcome: "ok", Namespace: r.Cfg.Namespace})
		r.writeProm(false, 0, false, false)
		return "Revoked the grant at OpenBao and removed local credentials.", nil
	}

	// Remove secondary credential copies (SSH cert, push token, artifacts) that cannot be revoked
	// at OpenBao, while preserving `.grant.json` expiry/recovery metadata until revocation is confirmed.
	var secErr error
	if stateErr == nil {
		secErr = files.removeSecondaryCredentials()
	}

	revoked := false
	confirmedByOpenBao := false
	upstreamNote := ""
	revokeErr := r.Client.RevokeSelf(ctx, token)
	switch {
	case revokeErr == nil:
		revoked = true
		confirmedByOpenBao = true
		upstreamNote = "revoked at OpenBao"
	case errors.Is(revokeErr, openbao.ErrInvalidToken):
		revoked = true
		confirmedByOpenBao = true
		upstreamNote = "already invalid or revoked at OpenBao"
	case errors.Is(revokeErr, openbao.ErrPermissionDenied):
		// HTTP 403 "permission denied" can mean either an ACL-denied live token OR a dead token.
		// Verify via LookupSelf before deciding; never delete the token file or state metadata
		// while the token is live or unconfirmed.
		info, lookupErr := r.Client.LookupSelf(ctx, token)
		switch {
		case lookupErr == nil && info.TTLSeconds > 0:
			revokeErr = fmt.Errorf("token is still active (%s left) but its policy denied auth/token/revoke-self", formatDuration(info.TTLSeconds))
		case errors.Is(lookupErr, openbao.ErrInvalidToken):
			revoked = true
			confirmedByOpenBao = true
			upstreamNote = "confirmed invalid at OpenBao"
		default:
			stateMatchesToken := stateErr == nil && stateExists && (state.RevokedTokenSHA256 == "" || state.RevokedTokenSHA256 == tokenDigest(token))
			if stateMatchesToken && state.TokenExpiresAt > 0 && r.Now().Unix() >= state.TokenExpiresAt {
				revoked = true
				upstreamNote = "recorded grant expiry elapsed (OpenBao denied revoke-self)"
			} else if lookupErr == nil {
				revokeErr = fmt.Errorf("OpenBao denied revoke-self and lookup-self returned ambiguous TTL 0")
			} else {
				revokeErr = fmt.Errorf("OpenBao denied revoke-self and could not confirm the token is invalid (%v)", lookupErr)
			}
		}
	}

	if !revoked {
		localErr := errors.Join(secErr, stateErr)
		auditErr := revokeErr
		if localErr != nil {
			auditErr = errors.Join(revokeErr, localErr)
		}
		r.emit(ctx, otel.Event{Action: "revoke", Outcome: "failed", Namespace: r.Cfg.Namespace, Error: auditErr.Error()})
		if localErr != nil {
			return "", fmt.Errorf("upstream: the grant was NOT revoked at OpenBao (%v). The token file was kept so you can retry; local cleanup/state error: %v", revokeErr, localErr)
		}
		return "", fmt.Errorf("the grant was NOT revoked at OpenBao (%v). The token file was kept so you can retry; other local files were deleted", revokeErr)
	}

	// Write confirmed retry evidence BEFORE removing token/state when OpenBao confirmed
	// revocation, so a subsequent removal failure cannot discard that evidence.
	// Local expiry alone never writes an OpenBao confirmation marker.
	var persistErr error
	retryStateSaved := false
	if confirmedByOpenBao && stateErr == nil {
		persistErr = r.recordRemoteConfirmation(state, token)
		retryStateSaved = (persistErr == nil)
	} else if !confirmedByOpenBao && stateErr == nil && stateExists {
		retryStateSaved = true
	}

	var tokenRmErr error
	if persistErr == nil && stateErr == nil {
		tokenRmErr = state.Parents.Token.remove(r.Cfg.TokenPath)
	}
	statePath := filepath.Join(r.Cfg.StateDir, stateFileName)
	var stateRmErr error
	if tokenRmErr == nil && secErr == nil && stateErr == nil && persistErr == nil {
		stateRmErr = removeRegularFile(statePath)
		if stateRmErr == nil {
			r.emit(ctx, otel.Event{Action: "revoke", Outcome: "ok", Namespace: r.Cfg.Namespace})
			r.writeProm(false, 0, false, false)
			if confirmedByOpenBao {
				return "Revoked the grant at OpenBao and removed local credentials.", nil
			}
			return "Grant expired locally (OpenBao denied revoke-self) and removed local credentials.", nil
		}
	}

	// Upstream/expiry succeeded, but local cleanup did not complete.
	localErr := errors.Join(tokenRmErr, secErr, stateErr, stateRmErr)
	if persistErr != nil {
		localErr = errors.Join(localErr, fmt.Errorf("persist retry state: %w", persistErr))
	}
	r.emit(ctx, otel.Event{Action: "revoke", Outcome: "failed", Namespace: r.Cfg.Namespace, Error: localErr.Error()})
	_, sshStatErr := os.Lstat(r.Cfg.SSHCertPath)
	_, pushStatErr := os.Lstat(r.Cfg.PushTokenPath)
	r.writeProm(tokenRmErr != nil, 0, sshStatErr == nil, pushStatErr == nil)
	if retryStateSaved {
		return "", fmt.Errorf("upstream: %s; local cleanup failed (%v); retry state was kept", upstreamNote, localErr)
	}
	return "", fmt.Errorf("upstream: %s; local cleanup failed (%v); retry state could not be updated", upstreamNote, localErr)
}

// PubKey returns the host's configured Ed25519 SSH public key for OpenBao SSH CA signing.
func (r *Receiver) PubKey() (string, error) {
	if strings.TrimSpace(r.Cfg.SSHPubKeyPath) == "" {
		return "", fmt.Errorf("ssh_pubkey_path is not configured on this receiver")
	}
	pub, err := readTrimmedFile(r.Cfg.SSHPubKeyPath)
	if err != nil {
		return "", fmt.Errorf("read ssh_pubkey_path: %w", err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || strings.ContainsAny(pub, "\r\n") {
		return "", fmt.Errorf("ssh_pubkey_path does not contain a single ssh-ed25519 public key")
	}
	return pub, nil
}

// Cleanup removes expired or revoked grant files (intended for a periodic systemd timer or cron).
func (r *Receiver) Cleanup(ctx context.Context) error {
	_, err := r.Status(ctx)
	return err
}

// Doctor checks the configuration, the state directory's permissions, and OpenBao connectivity.
func (r *Receiver) Doctor(ctx context.Context) (string, error) {
	var b strings.Builder
	var problems []string

	if fi, err := os.Stat(r.Cfg.StateDir); err != nil {
		problems = append(problems, fmt.Sprintf("state_dir %s: %v (create it, e.g. with the tmpfiles.d entry in deploy/)", r.Cfg.StateDir, err))
	} else {
		fmt.Fprintf(&b, "State dir: %s (mode %#o)\n", r.Cfg.StateDir, fi.Mode().Perm())
		if err := verifyControlFileOwner(fi); err != nil {
			problems = append(problems, fmt.Sprintf("untrusted state_dir: %v", err))
		}
		if fi.Mode().Perm()&0o007 != 0 {
			problems = append(problems, fmt.Sprintf("state_dir %s is accessible to other users (mode %#o); use 0750 or 0700", r.Cfg.StateDir, fi.Mode().Perm()))
		}
		if probe, err := os.CreateTemp(r.Cfg.StateDir, ".doctor-*"); err != nil {
			problems = append(problems, fmt.Sprintf("state_dir %s isn't writable: %v", r.Cfg.StateDir, err))
		} else {
			_ = probe.Close()
			_ = os.Remove(probe.Name())
		}
	}
	fmt.Fprintf(&b, "File mode: %#o\n", uint32(r.Cfg.FileMode))

	version, sealed, err := r.Client.CheckHealth(ctx)
	if err != nil {
		problems = append(problems, fmt.Sprintf("OpenBao health check failed: %v", err))
	} else {
		state := "unsealed"
		if sealed {
			state = "SEALED"
			problems = append(problems, "OpenBao is sealed")
		}
		fmt.Fprintf(&b, "OpenBao:   %s (v%s, %s)\n", config.EndpointOrigin(r.Cfg.OpenBaoAddr), version, state)
	}
	if r.Cfg.Namespace != "" {
		fmt.Fprintf(&b, "Namespace: %s\n", r.Cfg.Namespace)
	}
	if r.Cfg.OTLPEndpoint != "" {
		fmt.Fprintf(&b, "OTLP:      %s\n", config.EndpointOrigin(r.Cfg.OTLPEndpoint))
	}
	if r.Cfg.MetricsFilePath != "" {
		fmt.Fprintf(&b, "Metrics:   %s\n", r.Cfg.MetricsFilePath)
	}
	if r.Exporter != nil {
		if err := r.Exporter.CheckLocalSinks(); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("%s\nProblems:\n  - %s", strings.TrimSpace(b.String()), strings.Join(problems, "\n  - "))
	}
	return strings.TrimSpace(b.String()), nil
}

// lock serializes every command that reads or changes grant files.
func (r *Receiver) lock(ctx context.Context, deferredCleanup *error) (func(), error) {
	if err := r.checkGrantPaths(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(r.Cfg.StateDir, 0o750); err != nil {
		return nil, fmt.Errorf("create state_dir: %w", err)
	}
	fi, err := os.Stat(r.Cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if err := verifyControlFileOwner(fi); err != nil {
		return nil, fmt.Errorf("untrusted state_dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(r.Cfg.StateDir, lockFileName), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			unlock := func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}
			if err := r.recoverInstall(); err != nil {
				var backupErr *backupCleanupError
				if deferredCleanup != nil && errors.As(err, &backupErr) {
					*deferredCleanup = backupErr
					return unlock, nil
				}
				unlock()
				return nil, fmt.Errorf("recover interrupted grant installation: %w", err)
			}
			return unlock, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("lock state_dir: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("another baobuddy-receiver command is still running")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Legacy group-readable state is supported. Only the receiver may change it.
func (r *Receiver) readState() (grantState, bool, error) {
	path := filepath.Join(r.Cfg.StateDir, stateFileName)
	raw, fi, exists, err := readRegularFileInfo(path, maxStateFileBytes)
	if !exists || err != nil {
		return grantState{}, exists, err
	}
	if err := verifyControlFileOwner(fi); err != nil {
		return grantState{}, true, fmt.Errorf("untrusted grant state: %w", err)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return grantState{}, true, fmt.Errorf("grant state file %s is empty", stateFileName)
	}
	var state grantState
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if err := dec.Decode(&state); err != nil {
		return grantState{}, true, fmt.Errorf("decode grant state %s: %w", stateFileName, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return grantState{}, true, fmt.Errorf("decode grant state %s: trailing data", stateFileName)
	}
	if state.TokenExpiresAt < 0 {
		return grantState{}, true, fmt.Errorf("grant state %s has negative token_expires_at", stateFileName)
	}
	for name, expiry := range state.ArtifactExpiresAt {
		if !isSafeArtifactName(name) || expiry <= 0 {
			return grantState{}, true, fmt.Errorf("grant state %s has invalid artifact expiry entry %q", stateFileName, name)
		}
	}
	if state.RevokedTokenSHA256 != "" && !isHex64(state.RevokedTokenSHA256) {
		return grantState{}, true, fmt.Errorf("grant state %s has invalid revoked_token_sha256", stateFileName)
	}
	if state.TokenExpiresAt == 0 && len(state.ArtifactExpiresAt) == 0 && state.RevokedTokenSHA256 == "" {
		return grantState{}, true, fmt.Errorf("grant state %s has no expiry or revocation metadata", stateFileName)
	}
	return state, true, nil
}

func verifyControlFileOwner(fi os.FileInfo) error {
	if fi == nil {
		return errors.New("missing file metadata")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unable to verify file owner")
	}
	// Administrators may provision a root-owned delivery directory and grant
	// write access specifically to the receiver. Control files stay receiver-owned.
	if int(st.Uid) != os.Geteuid() && !(fi.IsDir() && st.Uid == 0) {
		return fmt.Errorf("owner uid %d does not match receiver euid %d", st.Uid, os.Geteuid())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("mode %#o permits group or world write", fi.Mode().Perm())
	}
	return nil
}

func (r *Receiver) readTokenFile() (string, bool, error) {
	raw, fi, exists, err := readRegularFileInfo(r.Cfg.TokenPath, maxTokenFileBytes)
	if !exists || err != nil {
		return "", exists, err
	}
	if err := verifyControlFileOwner(fi); err != nil {
		return "", true, fmt.Errorf("untrusted token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", true, fmt.Errorf("token file %s is empty", filepath.Base(r.Cfg.TokenPath))
	}
	if !isValidToken(token) {
		return "", true, fmt.Errorf("token file %s has invalid OpenBao token format", filepath.Base(r.Cfg.TokenPath))
	}
	return token, true, nil
}

func (r *Receiver) recordRemoteConfirmation(state grantState, token string) error {
	state.RevokedTokenSHA256 = tokenDigest(token)
	rawState, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return r.writePrivateAtomic(filepath.Join(r.Cfg.StateDir, stateFileName), string(rawState))
}

func (r *Receiver) sweepExpiredArtifacts(state grantState, now time.Time) error {
	if len(state.ArtifactExpiresAt) == 0 {
		return nil
	}
	dir := filepath.Join(r.Cfg.StateDir, artifactsDirName)
	fi, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", artifactsDirName, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("expected directory at %s, found %s", artifactsDirName, fi.Mode().Type())
	}
	var errs []error
	for name, expiry := range state.ArtifactExpiresAt {
		if isSafeArtifactName(name) && now.Unix() >= expiry {
			if err := removeRegularFile(filepath.Join(dir, name)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// removeSecondaryCredentials deletes delivered secondary credentials (SSH cert, push token,
// artifacts) while keeping the token and expiry state metadata intact for retry/cleanup.
// Plain-file paths are never removed if they point to a directory or non-regular file.
func (r grantFiles) removeSecondaryCredentials() error {
	return errors.Join(
		r.backupErr,
		r.parents.SSH.remove(r.Cfg.SSHCertPath),
		r.parents.Push.remove(r.Cfg.PushTokenPath),
		r.removeArtifactsDir(),
	)
}

// removeSecondaryFiles deletes everything a grant delivered except the token itself, including
// the `.grant.json` expiry state file. `.grant.json` is retained if any secondary removal fails.
func (r grantFiles) removeSecondaryFiles() error {
	if err := r.removeSecondaryCredentials(); err != nil {
		return err
	}
	return removeRegularFile(filepath.Join(r.Cfg.StateDir, stateFileName))
}

// removeAllGrantFiles deletes the token, secondary credentials, and `.grant.json`.
// `.grant.json` is retained if removing the token or any secondary credential fails.
func (r grantFiles) removeAllGrantFiles() error {
	tokenErr := r.parents.Token.remove(r.Cfg.TokenPath)
	secErr := r.removeSecondaryCredentials()
	if tokenErr != nil || secErr != nil {
		return errors.Join(tokenErr, secErr)
	}
	return removeRegularFile(filepath.Join(r.Cfg.StateDir, stateFileName))
}

func (r *Receiver) removeArtifactsDir() error {
	dir := filepath.Join(r.Cfg.StateDir, artifactsDirName)
	fi, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", artifactsDirName, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("refusing to remove non-directory %s (mode %s)", artifactsDirName, fi.Mode().Type())
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", artifactsDirName, err)
	}
	return nil
}

// readRegularFile opens a plain file without following symlinks and returns (nil, false, nil)
// only on genuine ENOENT. Unreadable files, symlinks, directories, non-regular files, and files
// exceeding maxBytes return exists=true with a non-nil error.
func readRegularFile(path string, maxBytes int64) ([]byte, bool, error) {
	raw, _, exists, err := readRegularFileInfo(path, maxBytes)
	return raw, exists, err
}

func readRegularFileInfo(path string, maxBytes int64) ([]byte, os.FileInfo, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, false, nil
		}
		return nil, nil, true, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, nil, true, fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	if fi.IsDir() {
		return nil, fi, true, fmt.Errorf("%s is a directory, expected regular file: %w", filepath.Base(path), syscall.EISDIR)
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, true, fmt.Errorf("%s is not a regular file (mode %s)", filepath.Base(path), fi.Mode().Type())
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fi, true, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fi, true, fmt.Errorf("%s exceeds %d bytes", filepath.Base(path), maxBytes)
	}
	return raw, fi, true, nil
}

func readOptionalRegularTrimmedFile(path string, maxBytes int64) (string, bool, error) {
	raw, exists, err := readRegularFile(path, maxBytes)
	if !exists || err != nil {
		return "", exists, err
	}
	return strings.TrimSpace(string(raw)), true, nil
}

// removeRegularFile unlinks a regular file without ever calling rmdir on a directory.
// Only genuine ENOENT is treated as already absent.
func removeRegularFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	if fi.IsDir() {
		return fmt.Errorf("refusing to remove directory %s as plain file: %w", filepath.Base(path), syscall.EISDIR)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove non-regular file %s (mode %s)", filepath.Base(path), fi.Mode().Type())
	}
	if err := syscall.Unlink(path); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("remove %s: %w", filepath.Base(path), err)
	}
	return nil
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (r *Receiver) writeAtomic(targetPath, content string) error {
	if err := r.Cfg.FileMode.Validate(); err != nil {
		return err
	}
	return writeAtomicFile(targetPath, content, os.FileMode(r.Cfg.FileMode), r.Cfg.FileOwnerGID)
}

func (r *Receiver) writePrivateAtomic(targetPath, content string) error {
	return writeAtomicFile(targetPath, content, 0600, 0)
}

func writeAtomicFile(targetPath, content string, mode os.FileMode, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(targetPath), ".baobuddy-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if gid > 0 {
		if err := tmp.Chown(-1, gid); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("set group %d on %s (the receiver user must be in that group): %w", gid, filepath.Base(targetPath), err)
		}
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// reject records a refused install and returns the error shown to the SSH client.
func (r *Receiver) reject(ctx context.Context, auditReason, message string) error {
	r.emit(ctx, otel.Event{Action: "install", Outcome: "rejected", Error: auditReason})
	return fmt.Errorf("refused: %s", message)
}

func (r *Receiver) emit(ctx context.Context, ev otel.Event) {
	if r.Exporter != nil {
		if err := r.Exporter.Emit(ctx, ev); err != nil {
			r.Warn(err.Error())
		}
	}
}

func (r *Receiver) writeProm(active bool, ttl int, sshActive, pushActive bool) {
	if r.Exporter != nil {
		if err := r.Exporter.WritePrometheusState(active, ttl, sshActive, pushActive); err != nil {
			r.Warn("could not publish the configured Prometheus metrics file")
		}
	}
}

func readLineTrimmed(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimSpace(line), err
}

func readTrimmedFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func isSafeArtifactName(name string) bool {
	if name == "" || len(name) > 64 || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func isValidToken(token string) bool {
	if token == "" || len(token) > 512 {
		return false
	}
	for _, r := range token {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func isValidPushTokenLine(line string) bool {
	if strings.ContainsAny(line, "\r\n\t") {
		return false
	}
	parts := strings.Split(line, " ")
	if len(parts) != 2 || parts[1] == "" || len(parts[1]) > 256 {
		return false
	}
	if _, err := strconv.ParseInt(parts[0], 10, 64); err != nil {
		return false
	}
	for _, r := range parts[1] {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func pushTokenRemaining(line string, now time.Time) (int, bool) {
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return 0, false
	}
	epoch, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return int(epoch - now.Unix()), true
}

func filterDefaultPolicy(policies []string) []string {
	var out []string
	for _, p := range policies {
		if p != "default" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return policies
	}
	return out
}

func formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
