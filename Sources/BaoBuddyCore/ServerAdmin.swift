import CryptoKit
import Foundation

public enum ServerAdminError: Error, LocalizedError, Equatable {
    case invalidPublicKeyPEM
    case missingAllowedPolicies
    case missingSubject
    case deviceKeyNotFound(String)
    case ambiguousFingerprint(String, Int)
    case sharedMount(mount: String, otherRole: String, otherSubject: String)
    case sharedGranterPolicy(policy: String, otherMount: String, otherSubject: String)
    case incompatibleGranterPolicy(policy: String, detail: String)
    case sharedTokenRole(tokenRole: String, otherMount: String, otherSubject: String)
    case notStaticKeyMount(String)
    case configUnreadable(String)
    case invalidName(String, String)

    public var errorDescription: String? {
        switch self {
        case .invalidPublicKeyPEM:
            return "Input is not a valid EC P-256 public key PEM (-----BEGIN PUBLIC KEY-----)."
        case .missingAllowedPolicies:
            return "Specify at least one allowed OpenBao policy (for example --policies db-readonly,k8s-deploy)."
        case .missingSubject:
            return "Specify a bound JWT subject (for example --subject alice)."
        case let .deviceKeyNotFound(prefix):
            return "No registered device key matched '\(prefix)'."
        case let .ambiguousFingerprint(prefix, count):
            return "Fingerprint prefix '\(prefix)' matched \(count) keys; provide more characters."
        case let .sharedMount(mount, otherRole, otherSubject):
            return """
            auth/\(mount)/ already has role '\(otherRole)' for subject '\(otherSubject)'. Every device key on a JWT mount \
            can sign in as any subject on it, so each person needs their own mount. Re-run with --mount jwt-<name>.
            """
        case let .sharedGranterPolicy(policy, otherMount, otherSubject):
            return """
            ACL policy '\(policy)' is already attached to auth/\(otherMount)/ (subject '\(otherSubject)'). \
            Reusing one granter policy across operators would couple their permissions; pass --granter-policy granter-<name>.
            """
        case let .incompatibleGranterPolicy(policy, detail):
            return "ACL policy '\(policy)' already exists with incompatible rules (\(detail)); refusing to overwrite it."
        case let .sharedTokenRole(tokenRole, otherMount, otherSubject):
            return """
            Token role '\(tokenRole)' is already granted to auth/\(otherMount)/ (subject '\(otherSubject)'). \
            Reusing one token role across operators would widen another operator's allowed policies; pass --token-role grant-<name>.
            """
        case let .invalidName(field, value):
            return "Invalid \(field) '\(value)': use letters, digits, and . _ - @ : (and / for paths); no quotes, spaces, '*', or '+'"
        case let .notStaticKeyMount(mount):
            return "auth/\(mount)/ is configured for OIDC discovery or JWKS, not static device keys; refusing to overwrite it."
        case let .configUnreadable(detail):
            return "Couldn't read the existing JWT config, so no keys were changed (writing now could de-register every device): \(detail)"
        }
    }
}

public struct RegisteredDeviceKey: Equatable, Sendable {
    public let pem: String
    public let fingerprint: String

    public init(pem: String, fingerprint: String) {
        self.pem = pem
        self.fingerprint = fingerprint
    }
}

public struct DeviceKeyAddResult: Equatable, Sendable {
    public let key: RegisteredDeviceKey
    public let added: Bool
    public let total: Int

    public init(key: RegisteredDeviceKey, added: Bool, total: Int) {
        self.key = key
        self.added = added
        self.total = total
    }
}

public struct ServerBootstrapOptions: Equatable, Sendable {
    public var mount: String
    public var role: String
    public var issuer: String
    public var audience: String
    public var subject: String
    public var granterPolicyName: String
    public var tokenRole: String
    public var allowedPolicies: [String]
    public var maxHours: Int
    public var boundCIDRs: [String]
    public var sshSignPath: String?
    public var githubTokenPath: String?
    public var initialPubKeys: [String]

    public init(
        mount: String? = nil,
        role: String = "granter",
        issuer: String = "bao-granter",
        audience: String? = nil,
        subject: String,
        granterPolicyName: String? = nil,
        tokenRole: String? = nil,
        allowedPolicies: [String],
        maxHours: Int = 12,
        boundCIDRs: [String] = [],
        sshSignPath: String? = nil,
        githubTokenPath: String? = nil,
        initialPubKeys: [String] = []
    ) {
        let effectiveMount: String
        if let resolvedMount = mount?.trimmingCharacters(in: .whitespacesAndNewlines), !resolvedMount.isEmpty {
            effectiveMount = resolvedMount
        } else {
            effectiveMount = BaoServerAdmin.defaultMount(subject: subject)
        }
        let effectivePolicy: String
        if let resolvedPolicy = granterPolicyName?.trimmingCharacters(in: .whitespacesAndNewlines), !resolvedPolicy.isEmpty {
            effectivePolicy = resolvedPolicy
        } else {
            effectivePolicy = BaoServerAdmin.defaultGranterPolicy(mount: effectiveMount, subject: subject)
        }
        let effectiveTokenRole: String
        if let resolvedTokenRole = tokenRole?.trimmingCharacters(in: .whitespacesAndNewlines), !resolvedTokenRole.isEmpty {
            effectiveTokenRole = resolvedTokenRole
        } else {
            effectiveTokenRole = BaoServerAdmin.defaultTokenRole(mount: effectiveMount, subject: subject)
        }
        self.mount = effectiveMount
        self.role = role
        self.issuer = issuer
        self.audience = audience?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        self.subject = subject
        self.granterPolicyName = effectivePolicy
        self.tokenRole = effectiveTokenRole
        self.allowedPolicies = allowedPolicies
        self.maxHours = max(1, min(maxHours, 24))
        self.boundCIDRs = boundCIDRs
        self.sshSignPath = sshSignPath
        self.githubTokenPath = githubTokenPath
        self.initialPubKeys = initialPubKeys
    }
}

/// First-class OpenBao / HashiCorp Vault admin client for bootstrapping BaoBuddy
/// JWT auth, token roles, and device public keys directly over HTTP without `make` or the `bao` CLI.
public struct BaoServerAdmin: Sendable {
    public let client: OpenBaoClient
    public let adminToken: String

    public init(client: OpenBaoClient, adminToken: String) {
        self.client = client
        self.adminToken = adminToken
    }

    /// Validates endpoint transport & TLS-pinning policy BEFORE building an admin `OpenBaoClient`,
    /// preventing admin tokens from ever being sent over non-loopback HTTP or unpinned TLS when
    /// pinning is required.
    public static func makeValidatedClient(
        address: String,
        namespace: String = "",
        caPEM: String = "",
        mtlsClientIdentity: String = "",
        enforceTLSPinning: Bool = false,
        transportFactory: ((String, String) throws -> any HTTPTransport)? = nil
    ) throws -> OpenBaoClient {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed) else {
            throw OpenBaoError.invalidBaseURL(address)
        }
        try OpenBaoClient.validateEndpointURL(url, allowDemo: false)
        let trimmedCA = caPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        if enforceTLSPinning && trimmedCA.isEmpty {
            throw ProfileError.invalidField(
                "openbao.ca_pem",
                "TLS certificate pinning is required by organization policy"
            )
        }
        let transport: any HTTPTransport
        if let transportFactory {
            transport = try transportFactory(trimmedCA, mtlsClientIdentity)
        } else {
            transport = try PinnedTLSClient(caPEM: trimmedCA, clientIdentityLabel: mtlsClientIdentity)
        }
        return OpenBaoClient(baseURL: url, transport: transport, namespace: namespace)
    }

    /// Sanitizes an operator name or mount suffix into a safe OpenBao identifier slug.
    public static func operatorSlug(mount: String, subject: String) -> String {
        let cleanMount = mount.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let candidate: String
        if cleanMount.lowercased().hasPrefix("jwt-") {
            let suffix = String(cleanMount.dropFirst(4))
            candidate = (suffix.isEmpty || suffix.lowercased() == "granter") ? subject : suffix
        } else {
            candidate = subject
        }
        let sanitized = sanitizeSlug(candidate)
        return sanitized.isEmpty ? "operator" : sanitized
    }

    public static func defaultMount(subject: String) -> String {
        let slug = sanitizeSlug(subject)
        return slug.isEmpty ? "jwt-granter" : "jwt-\(slug)"
    }

    public static func defaultTokenRole(mount: String, subject: String) -> String {
        "grant-\(operatorSlug(mount: mount, subject: subject))"
    }

    public static func defaultGranterPolicy(mount: String, subject: String) -> String {
        "granter-\(operatorSlug(mount: mount, subject: subject))"
    }

    public static func defaultAudience(
        address: String,
        namespace: String = "",
        mount: String,
        caPEM: String = "",
        mtlsClientIdentity: String = ""
    ) -> String {
        BaoOpenBaoConfig.defaultAudience(
            address: address,
            namespace: namespace,
            mount: mount,
            caPEM: caPEM,
            mtlsClientIdentity: mtlsClientIdentity
        )
    }

    /// Formats a shell-safe `bao-buddy device add` command preserving deployment, namespace,
    /// TLS CA cert path, mTLS identity, and JWT mount context.
    public static func renderDeviceAddCommand(
        address: String,
        namespace: String = "",
        caCertPath: String = "",
        mtlsClientIdentity: String = "",
        mount: String,
        selfKey: Bool = false
    ) -> String {
        var parts = ["bao-buddy", "device", "add"]
        let trimmedAddr = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedAddr.isEmpty {
            parts += ["--addr", trimmedAddr]
        }
        let trimmedNS = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedNS.isEmpty {
            parts += ["--namespace", trimmedNS]
        }
        let trimmedCA = caCertPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedCA.isEmpty {
            parts += ["--cacert", trimmedCA]
        }
        let trimmedMTLS = mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedMTLS.isEmpty {
            parts += ["--mtls-identity", trimmedMTLS]
        }
        parts += ["--mount", mount]
        if selfKey {
            parts.append("--self")
        }
        return parts.map(shellQuoteArg).joined(separator: " ")
    }

    /// Renders server-first next-step commands after `bao-buddy server-setup`:
    /// 1. Export/import the server profile FIRST (preserving address, namespace, CA cert, mTLS, mount, role, issuer, audience, token role, max hours, and GitHub path).
    /// 2. Create the server-scoped Hardware Approval Key on iPhone for that imported profile and copy its PEM.
    /// 3. Register the copied iPhone PEM on OpenBao using the preserved deployment context.
    public static func renderSetupNextSteps(
        address: String,
        namespace: String = "",
        caCertPath: String = "",
        mtlsClientIdentity: String = "",
        mount: String,
        role: String = "granter",
        issuer: String = "bao-granter",
        customAudience: String? = nil,
        tokenRole: String,
        maxHours: Int = 12,
        policies: [String],
        subject: String,
        githubTokenPath: String? = nil
    ) -> String {
        var exportParts = ["bao-buddy", "export-profile"]
        let trimmedAddr = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedAddr.isEmpty {
            exportParts += ["--addr", trimmedAddr]
        }
        let trimmedNS = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedNS.isEmpty {
            exportParts += ["--namespace", trimmedNS]
        }
        let trimmedCA = caCertPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedCA.isEmpty {
            exportParts += ["--cacert", trimmedCA]
        }
        let trimmedMTLS = mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedMTLS.isEmpty {
            exportParts += ["--mtls-identity", trimmedMTLS]
        }
        exportParts += ["--mount", mount]
        if role != "granter" {
            exportParts += ["--role", role]
        }
        if issuer != "bao-granter" {
            exportParts += ["--issuer", issuer]
        }
        if let customAudience = customAudience?.trimmingCharacters(in: .whitespacesAndNewlines), !customAudience.isEmpty {
            exportParts += ["--audience", customAudience]
        }
        if tokenRole != defaultTokenRole(mount: mount, subject: subject) {
            exportParts += ["--token-role", tokenRole]
        }
        if maxHours != 12 {
            exportParts += ["--max-hours", "\(maxHours)"]
        }
        if let gh = githubTokenPath?.trimmingCharacters(in: .whitespacesAndNewlines), !gh.isEmpty {
            exportParts += ["--github-token-path", gh]
        }
        exportParts += ["--subject", subject, "--policies", policies.joined(separator: ","), "--copy", "--save"]

        let exportCmd = exportParts.map(shellQuoteArg).joined(separator: " ")
        let deviceAddCmd = renderDeviceAddCommand(
            address: trimmedAddr,
            namespace: trimmedNS,
            caCertPath: trimmedCA,
            mtlsClientIdentity: trimmedMTLS,
            mount: mount
        )
        return """
        Next steps:
          1. Export and save the server profile first (copied for iPhone + saved for this Mac):
             \(exportCmd)
          2. On iPhone: open BaoBuddy -> Set Up First Server -> Paste Profile JSON from Clipboard (or add `--qr` above), then create its server-scoped Hardware Approval Key and copy its P-256 PEM.
          3. Register that iPhone key on OpenBao:
             pbpaste | \(deviceAddCmd)
        """
    }

    private static func shellQuoteArg(_ word: String) -> String {
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./,=:@")
        if !word.isEmpty && word.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return word
        }
        return "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func sanitizeSlug(_ raw: String) -> String {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._-")
        let lowered = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let filtered = String(lowered.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" })
        return filtered.trimmingCharacters(in: CharacterSet(charactersIn: "-_."))
    }

    /// Validates that `raw` is an EC P-256 public key PEM and returns its canonical PEM + SHA-256 fingerprint.
    public static func validateP256PEM(_ raw: String) throws -> RegisteredDeviceKey {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw ServerAdminError.invalidPublicKeyPEM
        }
        do {
            let key = try P256.Signing.PublicKey(pemRepresentation: trimmed)
            let fp = try PEMCodec.spkiFingerprint(x963Data: key.x963Representation)
            return RegisteredDeviceKey(pem: key.pemRepresentation, fingerprint: fp)
        } catch {
            throw ServerAdminError.invalidPublicKeyPEM
        }
    }

    /// Builds the least-privilege `granter` policy. The sign-in token gets no `default` policy,
    /// so every path it needs is listed here:
    /// - mint grants through one token role (no `sudo`: role-based orphan tokens don't need it,
    ///   and `sudo` would allow root-protected options such as choosing the token ID);
    /// - revoke a grant whose delivery failed, by value or by accessor;
    /// - revoke itself when done;
    /// - optionally sign SSH certificates and mint GitHub tokens through a server-side endpoint.
    /// It never gets read access to secrets.
    public static func granterPolicyHCL(
        tokenRole: String,
        sshSignPath: String? = nil,
        githubTokenPath: String? = nil
    ) -> String {
        var blocks: [(String, [String])] = [
            ("auth/token/create/\(tokenRole)", ["create", "update"]),
            ("auth/token/revoke", ["update"]),
            ("auth/token/revoke-accessor", ["update"]),
            ("auth/token/revoke-self", ["update"])
        ]
        for optional in [sshSignPath, githubTokenPath] {
            // `bootstrap` rejects unsafe paths; this guard keeps other callers from emitting them.
            if let path = optional?.trimmingCharacters(in: .whitespacesAndNewlines), !path.isEmpty,
               ProfileText.isAPIPath(path) {
                blocks.append((path, ["create", "update"]))
            }
        }
        return blocks.map { path, caps in
            let list = caps.map { "\"\($0)\"" }.joined(separator: ", ")
            return "path \"\(path)\" {\n  capabilities = [\(list)]\n}"
        }.joined(separator: "\n\n") + "\n"
    }

    /// Settings for the JWT login role. The leeways default to 150 s (expiry) and 60 s (clock
    /// skew) in Vault's JWT auth, which would stretch a 30-second JWT to about 3 minutes; these
    /// keep it close to 30 s. There's no `token_num_uses`: Vault doesn't let a use-limited token
    /// create other tokens, so the 2-minute TTL is the limit.
    public static func loginRoleBody(
        subject: String,
        audience: String,
        granterPolicyName: String,
        boundCIDRs: [String]
    ) -> [String: Any] {
        var body: [String: Any] = [
            "role_type": "jwt",
            "user_claim": "sub",
            "bound_subject": subject,
            "bound_audiences": [audience],
            "token_policies": [granterPolicyName],
            "token_no_default_policy": true,
            "token_ttl": "2m",
            "token_max_ttl": "2m",
            "expiration_leeway": 5,
            "not_before_leeway": 5,
            "clock_skew_leeway": 5,
            // Copied into the sign-in token's metadata so audit logs show the device name and the
            // scope the user approved. Both are claims the device chose: useful for review, not proof.
            "claim_mappings": ["device": "device", "scope": "scope"]
        ]
        if !boundCIDRs.isEmpty {
            body["token_bound_cidrs"] = boundCIDRs
        }
        return body
    }

    /// Idempotently configures the granter ACL policy, scoped token role, ES256 JWT auth mount,
    /// and JWT login role on OpenBao / HashiCorp Vault.
    public func bootstrap(_ opts: ServerBootstrapOptions) async throws -> [String] {
        let subject = opts.subject.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !subject.isEmpty else { throw ServerAdminError.missingSubject }
        let policies = opts.allowedPolicies.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        guard !policies.isEmpty else { throw ServerAdminError.missingAllowedPolicies }
        // Every name below is written into policy HCL or an API path. Reject anything that could
        // change the policy's meaning (quotes, braces, newlines) or widen it ('*', '+' globs).
        for (field, value) in [("subject", subject), ("role", opts.role), ("token role", opts.tokenRole),
                               ("granter policy", opts.granterPolicyName)] + policies.map({ ("policy", $0) }) {
            guard ProfileText.isIdentifier(value) else { throw ServerAdminError.invalidName(field, value) }
        }
        for (field, value) in [("mount", opts.mount), ("ssh sign path", opts.sshSignPath ?? ""),
                               ("github token path", opts.githubTokenPath ?? "")] where !value.isEmpty {
            guard ProfileText.isAPIPath(value) else { throw ServerAdminError.invalidName(field, value) }
        }
        guard !policies.contains("root") else { throw ServerAdminError.invalidName("policy", "root") }

        let effectiveAudience = opts.audience.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? Self.defaultAudience(address: client.baseURL.absoluteString, namespace: client.namespace, mount: opts.mount)
            : opts.audience.trimmingCharacters(in: .whitespacesAndNewlines)

        var steps: [String] = []

        // 0. One identity per mount, granter policy, and token role: inspect existing mounts and
        //    ACL policies BEFORE writing anything so adding an operator never widens another's access.
        let mounts = try await client.get(path: "v1/sys/auth", token: adminToken)
        let mountKey = opts.mount.hasSuffix("/") ? opts.mount : "\(opts.mount)/"
        let authMap = (mounts["data"] as? [String: Any]) ?? mounts
        let mountExists = authMap[mountKey] != nil
        if mountExists {
            try await ensureMountBelongsTo(subject: subject, mount: opts.mount, role: opts.role)
        }
        try await ensureIsolatedOperatorObjects(
            authMap: authMap,
            targetMount: opts.mount,
            granterPolicyName: opts.granterPolicyName,
            tokenRole: opts.tokenRole
        )

        // 1. Least-privilege granter policy.
        let hcl = Self.granterPolicyHCL(
            tokenRole: opts.tokenRole,
            sshSignPath: opts.sshSignPath,
            githubTokenPath: opts.githubTokenPath
        )
        _ = try await client.putJSONObject(
            path: "v1/sys/policies/acl/\(opts.granterPolicyName)",
            token: adminToken,
            body: ["policy": hcl]
        )
        steps.append("Wrote least-privilege policy '\(opts.granterPolicyName)' (token role '\(opts.tokenRole)').")

        // 2. Orphan, non-renewable token role. BaoBuddy also checks every minted token against these.
        _ = try await client.postJSONObject(
            path: "v1/auth/token/roles/\(opts.tokenRole)",
            token: adminToken,
            body: [
                "allowed_policies": policies,
                "disallowed_policies": ["root"],
                "orphan": true,
                "renewable": false,
                "token_explicit_max_ttl": "\(opts.maxHours)h"
            ]
        )
        steps.append("Configured token role '\(opts.tokenRole)' (policies: \(policies.joined(separator: ", ")), max TTL: \(opts.maxHours)h).")

        // 3. JWT auth mount.
        if !mountExists {
            _ = try await client.postJSONObject(
                path: "v1/sys/auth/\(opts.mount)",
                token: adminToken,
                body: ["type": "jwt", "description": "BaoBuddy device keys for \(subject)"]
            )
            steps.append("Enabled JWT auth mount at 'auth/\(opts.mount)/'.")
        } else {
            steps.append("JWT auth mount 'auth/\(opts.mount)/' already enabled.")
        }

        // 4. Device keys: merge, never replace.
        var existing = mountExists ? try await readKeyConfig(mount: opts.mount) : KeyConfig.empty
        for rawPEM in opts.initialPubKeys {
            let validated = try Self.validateP256PEM(rawPEM)
            if !existing.keys.contains(where: { $0.fingerprint == validated.fingerprint }) {
                existing.keys.append(validated)
            }
        }
        existing.issuer = opts.issuer
        try await writeKeyConfig(mount: opts.mount, config: existing)
        steps.append("Configured 'auth/\(opts.mount)/config' (ES256, \(existing.keys.count) device key(s)).")

        // 5. JWT login role.
        _ = try await client.postJSONObject(
            path: "v1/auth/\(opts.mount)/role/\(opts.role)",
            token: adminToken,
            body: Self.loginRoleBody(
                subject: subject,
                audience: effectiveAudience,
                granterPolicyName: opts.granterPolicyName,
                boundCIDRs: opts.boundCIDRs
            )
        )
        steps.append("Configured JWT role '\(opts.role)' for subject '\(subject)' (audience: \(effectiveAudience)).")
        return steps
    }

    /// Ensures `granterPolicyName` and `tokenRole` are not already owned by another JWT mount/operator
    /// or by an incompatible pre-existing ACL policy.
    func ensureIsolatedOperatorObjects(
        authMap: [String: Any],
        targetMount: String,
        granterPolicyName: String,
        tokenRole: String
    ) async throws {
        let normalizedTarget = targetMount.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        // Check if an existing ACL policy at `granterPolicyName` points at a different token role or unrelated paths.
        if let existingPolicyHCL = try await readACLPolicy(name: granterPolicyName) {
            let referencedRoles = Self.extractTokenCreateRoles(from: existingPolicyHCL)
            if referencedRoles.contains(where: { $0 != tokenRole }) {
                let others = referencedRoles.filter { $0 != tokenRole }.sorted().joined(separator: ", ")
                throw ServerAdminError.incompatibleGranterPolicy(
                    policy: granterPolicyName,
                    detail: "grants auth/token/create for different role(s): \(others)"
                )
            }
            if referencedRoles.isEmpty {
                throw ServerAdminError.incompatibleGranterPolicy(
                    policy: granterPolicyName,
                    detail: "does not appear to be a BaoBuddy granter policy for '\(tokenRole)'"
                )
            }
        }

        // Inspect all other JWT mounts in this namespace for shared granter policies or shared token roles.
        let targetCreatePath = "auth/token/create/\(tokenRole)"
        var checkedPolicies: [String: String?] = [:]
        for (rawKey, rawValue) in authMap {
            guard let mountMeta = rawValue as? [String: Any],
                  (mountMeta["type"] as? String)?.lowercased() == "jwt" else {
                continue
            }
            let otherMount = rawKey.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            guard otherMount != normalizedTarget else { continue }

            let otherRoles = try await client.list(path: "v1/auth/\(otherMount)/role", token: adminToken)
            for otherRole in otherRoles {
                let json = try await client.get(path: "v1/auth/\(otherMount)/role/\(otherRole)", token: adminToken)
                let data = json["data"] as? [String: Any] ?? [:]
                let otherSubject = (data["bound_subject"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? otherRole
                let attachedPolicies = (data["token_policies"] as? [String])
                    ?? (data["policies"] as? [String])
                    ?? []
                if attachedPolicies.contains(granterPolicyName) {
                    throw ServerAdminError.sharedGranterPolicy(
                        policy: granterPolicyName,
                        otherMount: otherMount,
                        otherSubject: otherSubject
                    )
                }
                for attached in attachedPolicies {
                    let hcl: String?
                    if let cached = checkedPolicies[attached] {
                        hcl = cached
                    } else {
                        let loaded = try await readACLPolicy(name: attached)
                        checkedPolicies[attached] = loaded
                        hcl = loaded
                    }
                    if let hcl, Self.extractTokenCreateRoles(from: hcl).contains(tokenRole) || hcl.contains("\"\(targetCreatePath)\"") {
                        throw ServerAdminError.sharedTokenRole(
                            tokenRole: tokenRole,
                            otherMount: otherMount,
                            otherSubject: otherSubject
                        )
                    }
                }
            }
        }
    }

    private func readACLPolicy(name: String) async throws -> String? {
        do {
            let json = try await client.get(path: "v1/sys/policies/acl/\(name)", token: adminToken)
            let data = json["data"] as? [String: Any] ?? json
            return (data["policy"] as? String) ?? (data["rules"] as? String)
        } catch OpenBaoError.httpError(404, _) {
            return nil
        }
    }

    static func extractTokenCreateRoles(from hcl: String) -> Set<String> {
        guard let regex = try? NSRegularExpression(pattern: #"auth/token/create/([A-Za-z0-9._@:-]+)"#) else {
            return []
        }
        let range = NSRange(hcl.startIndex..<hcl.endIndex, in: hcl)
        var roles = Set<String>()
        for match in regex.matches(in: hcl, range: range) where match.numberOfRanges >= 2 {
            if let r = Range(match.range(at: 1), in: hcl) {
                roles.insert(String(hcl[r]))
            }
        }
        return roles
    }

    /// Every key on a JWT mount can sign in to every role on it, so a mount must serve one subject.
    func ensureMountBelongsTo(subject: String, mount: String, role: String) async throws {
        let roles = try await client.list(path: "v1/auth/\(mount)/role", token: adminToken)
        for other in roles {
            let json = try await client.get(path: "v1/auth/\(mount)/role/\(other)", token: adminToken)
            let data = json["data"] as? [String: Any] ?? [:]
            let bound = data["bound_subject"] as? String ?? ""
            if bound != subject {
                throw ServerAdminError.sharedMount(mount: mount, otherRole: other, otherSubject: bound.isEmpty ? "(any)" : bound)
            }
        }
    }

    /// The parts of `auth/<mount>/config` BaoBuddy manages, plus anything it must carry over.
    struct KeyConfig {
        var keys: [RegisteredDeviceKey]
        /// Keys BaoBuddy can't parse (for example RSA keys someone added by hand). Kept as-is.
        var otherKeys: [String]
        var issuer: String
        var algorithms: [String]
        var defaultRole: String

        static let empty = KeyConfig(keys: [], otherKeys: [], issuer: "", algorithms: [], defaultRole: "")
    }

    /// Reads the mount's key config. Fails rather than returning an empty list, because writing an
    /// empty list back would de-register every device.
    func readKeyConfig(mount: String) async throws -> KeyConfig {
        let json: [String: Any]
        do {
            json = try await client.get(path: "v1/auth/\(mount)/config", token: adminToken)
        } catch OpenBaoError.httpError(404, _) {
            return .empty
        } catch {
            throw ServerAdminError.configUnreadable(error.localizedDescription)
        }
        let data = json["data"] as? [String: Any] ?? [:]
        let discovery = data["oidc_discovery_url"] as? String ?? ""
        let jwks = data["jwks_url"] as? String ?? ""
        if !discovery.isEmpty || !jwks.isEmpty {
            throw ServerAdminError.notStaticKeyMount(mount)
        }
        var config = KeyConfig.empty
        for raw in data["jwt_validation_pubkeys"] as? [String] ?? [] {
            if let key = try? Self.validateP256PEM(raw) {
                config.keys.append(key)
            } else {
                config.otherKeys.append(raw)
            }
        }
        config.issuer = data["bound_issuer"] as? String ?? ""
        config.algorithms = data["jwt_supported_algs"] as? [String] ?? []
        config.defaultRole = data["default_role"] as? String ?? ""
        return config
    }

    /// Writes the key config back with every field BaoBuddy read, because a config write replaces
    /// fields it doesn't mention. Concurrent edits by two admins can still race; Vault offers no
    /// compare-and-set for auth config.
    func writeKeyConfig(mount: String, config: KeyConfig) async throws {
        var algorithms = config.algorithms
        if !algorithms.contains("ES256") { algorithms.append("ES256") }
        var body: [String: Any] = [
            "bound_issuer": config.issuer,
            "jwt_supported_algs": algorithms,
            "jwt_validation_pubkeys": config.keys.map(\.pem) + config.otherKeys
        ]
        if !config.defaultRole.isEmpty {
            body["default_role"] = config.defaultRole
        }
        _ = try await client.postJSONObject(path: "v1/auth/\(mount)/config", token: adminToken, body: body)
    }

    /// Reads registered device public keys from `auth/<mount>/config`.
    public func listDeviceKeys(mount: String) async throws -> [RegisteredDeviceKey] {
        try await readKeyConfig(mount: mount).keys
    }

    /// Registers a device's EC P-256 public key PEM on `auth/<mount>/config`, keeping existing keys.
    public func addDeviceKey(
        mount: String,
        pem: String,
        defaultIssuer: String = "bao-granter"
    ) async throws -> DeviceKeyAddResult {
        let validated = try Self.validateP256PEM(pem)
        var config = try await readKeyConfig(mount: mount)
        if config.issuer.isEmpty { config.issuer = defaultIssuer }
        let added: Bool
        if config.keys.contains(where: { $0.fingerprint == validated.fingerprint }) {
            added = false
        } else {
            config.keys.append(validated)
            added = true
        }
        try await writeKeyConfig(mount: mount, config: config)
        return DeviceKeyAddResult(key: validated, added: added, total: config.keys.count + config.otherKeys.count)
    }

    /// Removes one registered device key by SHA-256 fingerprint prefix (with or without `sha256:`).
    /// This stops new sign-ins from that device. It doesn't revoke grants the device already
    /// minted, or its SSH key on a remote granter host; see docs/THREAT_MODEL.md.
    public func removeDeviceKey(
        mount: String,
        fingerprintPrefix: String
    ) async throws -> (removed: RegisteredDeviceKey, remaining: Int) {
        let normalized = fingerprintPrefix
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "sha256:", with: "")
        guard !normalized.isEmpty else {
            throw ServerAdminError.deviceKeyNotFound(fingerprintPrefix)
        }
        var config = try await readKeyConfig(mount: mount)
        let matches = config.keys.filter { $0.fingerprint.lowercased().hasPrefix(normalized) }
        guard !matches.isEmpty else {
            throw ServerAdminError.deviceKeyNotFound(fingerprintPrefix)
        }
        guard matches.count == 1, let target = matches.first else {
            throw ServerAdminError.ambiguousFingerprint(fingerprintPrefix, matches.count)
        }
        config.keys.removeAll { $0.fingerprint == target.fingerprint }
        try await writeKeyConfig(mount: mount, config: config)
        return (target, config.keys.count + config.otherKeys.count)
    }

    /// Reads `allowed_policies` from `auth/token/roles/<role>` if accessible.
    public func readTokenRolePolicies(role: String) async throws -> [String] {
        let json = try await client.get(path: "v1/auth/token/roles/\(role)", token: adminToken)
        let data = json["data"] as? [String: Any] ?? [:]
        return data["allowed_policies"] as? [String] ?? []
    }
}
