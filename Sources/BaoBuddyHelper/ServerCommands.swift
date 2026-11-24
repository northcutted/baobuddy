#if os(macOS)
import AppKit
import BaoBuddyCore
import Foundation

/// Standalone OpenBao / HashiCorp Vault admin & onboarding commands built into `bao-buddy`,
/// so any user can bootstrap a server, register devices, and export profiles without `make` or scripts.
enum ServerCommands {
    static func runServerSetup(args: [String], deviceName: String = "mac") async throws {
        let opts = BaoBuddyHelperCLI.parseFlags(args)
        let adminCtx = try makeAdminClient(opts: opts)
        let client = adminCtx.client
        let token = adminCtx.token

        let subject = opts["subject"] ?? ProcessInfo.processInfo.environment["USER"] ?? ""
        let mount = opts["mount"] ?? BaoServerAdmin.defaultMount(subject: subject)
        let role = opts["role"] ?? "granter"
        let issuer = opts["issuer"] ?? "bao-granter"
        let audience = opts["audience"] ?? BaoServerAdmin.defaultAudience(
            address: client.baseURL.absoluteString,
            namespace: client.namespace,
            mount: mount,
            caPEM: adminCtx.caPEM,
            mtlsClientIdentity: adminCtx.mtlsIdentity
        )
        let tokenRole = opts["token-role"] ?? BaoServerAdmin.defaultTokenRole(mount: mount, subject: subject)
        let granterPolicy = opts["granter-policy"] ?? BaoServerAdmin.defaultGranterPolicy(mount: mount, subject: subject)
        let maxHours = Int(opts["max-hours"] ?? "12") ?? 12
        let policies = splitCSV(opts["policies"])
        let cidrs = splitCSV(opts["cidrs"])
        let sshSignPath = opts["ssh-sign-path"]
        let githubTokenPath = opts["github-token-path"]

        var initialPEMs: [String] = []
        if opts["add-self"] != nil {
            let scopedStore = SecureEnclaveKeyStore.scoped(
                address: client.baseURL.absoluteString,
                namespace: client.namespace,
                mount: mount,
                caPEM: adminCtx.caPEM,
                mtlsClientIdentity: adminCtx.mtlsIdentity,
                deviceName: deviceName
            )
            initialPEMs.append(try scopedStore.ensureKey(overwrite: false))
        }
        if let pemFile = opts["pubkey-file"], !pemFile.isEmpty {
            initialPEMs.append(try String(contentsOfFile: pemFile, encoding: .utf8))
        }

        let admin = BaoServerAdmin(client: client, adminToken: token)
        let steps = try await admin.bootstrap(
            ServerBootstrapOptions(
                mount: mount,
                role: role,
                issuer: issuer,
                audience: audience,
                subject: subject,
                granterPolicyName: granterPolicy,
                tokenRole: tokenRole,
                allowedPolicies: policies,
                maxHours: maxHours,
                boundCIDRs: cidrs,
                sshSignPath: sshSignPath,
                githubTokenPath: githubTokenPath,
                initialPubKeys: initialPEMs
            )
        )
        for line in steps {
            print("  \(line)")
        }
        print("""

        Notes:
          - auth/\(mount)/, policy '\(granterPolicy)', and token role '\(tokenRole)' now belong to '\(subject)'.
            Give each other person their own mount (--mount jwt-<name>) so roles and policies stay isolated.
          - The server can't see what was approved in the app: any registered device can mint any of
            [\(policies.joined(separator: ", "))] for up to \(maxHours)h. Keep that list as small as you can.
        """)
        print("\n" + BaoServerAdmin.renderSetupNextSteps(
            address: client.baseURL.absoluteString,
            namespace: client.namespace,
            caCertPath: adminCtx.caCertPath,
            mtlsClientIdentity: adminCtx.mtlsIdentity,
            mount: mount,
            role: role,
            issuer: issuer,
            customAudience: opts["audience"],
            tokenRole: tokenRole,
            maxHours: maxHours,
            policies: policies,
            subject: subject,
            githubTokenPath: githubTokenPath
        ))
    }

    static func runDevice(args: [String], deviceName: String = "mac") async throws {
        guard let action = args.first else {
            fputs("usage: bao-buddy device <add|list|remove> [options]\n", stderr)
            exit(2)
        }
        let rest = Array(args.dropFirst())
        let opts = BaoBuddyHelperCLI.parseFlags(rest)
        let adminCtx = try makeAdminClient(opts: opts)
        let defaultMount = (try? BaoBuddyHelperCLI.loadActiveProfile(selector: opts["profile"]).openbao.jwtAuth.mount)
            ?? "jwt-granter"
        let mount = opts["mount"] ?? defaultMount
        let admin = BaoServerAdmin(client: adminCtx.client, adminToken: adminCtx.token)

        switch action {
        case "list":
            let keys = try await admin.listDeviceKeys(mount: mount)
            if keys.isEmpty {
                print("No device public keys registered on auth/\(mount)/.")
            } else {
                for (idx, key) in keys.enumerated() {
                    print("  \(idx + 1). sha256:\(key.fingerprint)")
                }
            }
        case "add":
            let rawPEM: String
            if opts["self"] != nil {
                let scopedStore = SecureEnclaveKeyStore.scoped(
                    address: adminCtx.client.baseURL.absoluteString,
                    namespace: adminCtx.client.namespace,
                    mount: mount,
                    caPEM: adminCtx.caPEM,
                    mtlsClientIdentity: adminCtx.mtlsIdentity,
                    deviceName: deviceName
                )
                rawPEM = try scopedStore.ensureKey(overwrite: false)
            } else if let file = opts["file"], !file.isEmpty {
                rawPEM = try String(contentsOfFile: file, encoding: .utf8)
            } else if opts["token-stdin"] != nil {
                throw OpenBaoError.unexpectedResponse(
                    "--token-stdin already reads the admin token from stdin; pass the device key with --file <pem>"
                )
            } else {
                let data = FileHandle.standardInput.readDataToEndOfFile()
                rawPEM = String(data: data, encoding: .utf8) ?? ""
            }
            let result = try await admin.addDeviceKey(
                mount: mount,
                pem: rawPEM,
                defaultIssuer: opts["issuer"] ?? "bao-granter"
            )
            if result.added {
                print("Registered device key sha256:\(result.key.fingerprint) on auth/\(mount)/ (\(result.total) total).")
            } else {
                print("Device key sha256:\(result.key.fingerprint) is already registered on auth/\(mount)/ (\(result.total) total).")
            }
        case "remove":
            let prefix = opts["fingerprint"] ?? BaoBuddyHelperCLI.positionalArgs(rest).first ?? ""
            let result = try await admin.removeDeviceKey(mount: mount, fingerprintPrefix: prefix)
            print("Removed device key sha256:\(result.removed.fingerprint) from auth/\(mount)/ (\(result.remaining) remaining).")
            print("""
            That device can't sign in any more. To finish cutting it off:
              1. Revoke grants it already minted (they last up to the token role's max TTL). Their
                 metadata has by=<subject> and via=<app|mac>; find accessors with
                 `bao list auth/token/accessors` and revoke them with `bao token revoke -accessor`.
              2. Remove its SSH key from any remote granter host's authorized_keys.
            """)
        default:
            fputs("bao-buddy device: unknown subcommand '\(action)' (expected add, list, or remove)\n", stderr)
            exit(2)
        }
    }

    static func runExportProfile(args: [String]) async throws {
        let opts = BaoBuddyHelperCLI.parseFlags(args)
        let addr = try resolveAddress(opts: opts)
        let namespace = resolveNamespace(opts: opts)
        let caPEM = try resolveCAPEM(opts: opts)
        let mtlsIdentity = opts["mtls-identity"] ?? ""
        let managed = ManagedAppConfig.load()

        // Validate endpoint transport and TLS-pinning policy BEFORE reading or sending any admin token.
        let validatedClient = try BaoServerAdmin.makeValidatedClient(
            address: addr,
            namespace: namespace,
            caPEM: caPEM,
            mtlsClientIdentity: mtlsIdentity,
            enforceTLSPinning: managed.enforceTLSPinning
        )

        let name = opts["name"] ?? validatedClient.baseURL.host ?? "OpenBao"
        let subject = opts["subject"] ?? ProcessInfo.processInfo.environment["USER"] ?? "user"
        let mount = opts["mount"] ?? BaoServerAdmin.defaultMount(subject: subject)
        let role = opts["role"] ?? "granter"
        let issuer = opts["issuer"] ?? "bao-granter"
        let audience = opts["audience"] ?? BaoServerAdmin.defaultAudience(
            address: addr,
            namespace: namespace,
            mount: mount,
            caPEM: caPEM,
            mtlsClientIdentity: mtlsIdentity
        )
        let tokenRole = opts["token-role"] ?? BaoServerAdmin.defaultTokenRole(mount: mount, subject: subject)
        let maxHours = Int(opts["max-hours"] ?? "12") ?? 12
        let auditPolicy = BaoAuditPolicy(
            requireReason: opts["require-reason"] != nil,
            requireReasonForElevated: opts["require-reason-elevated"] != nil,
            reasonPattern: opts["reason-pattern"] ?? "",
            reasonPlaceholder: opts["reason-placeholder"] ?? ""
        )

        var policyNames = splitCSV(opts["policies"])
        if policyNames.isEmpty, let token = try resolveOptionalToken(opts: opts) {
            let admin = BaoServerAdmin(client: validatedClient, adminToken: token)
            if let discovered = try? await admin.readTokenRolePolicies(role: tokenRole), !discovered.isEmpty {
                policyNames = discovered
            }
        }
        if caPEM.isEmpty {
            fputs("warning: no BAO_CACERT/--cacert, so the profile trusts the system CA store instead of pinning a certificate.\n", stderr)
        }
        let elevatedSet = Set(splitCSV(opts["elevated"]))
        let grantPolicies = policyNames.enumerated().map { idx, policyName in
            BaoBuddyPolicy(
                name: policyName,
                elevated: elevatedSet.contains(policyName),
                defaultSelected: idx == 0 && !elevatedSet.contains(policyName)
            )
        }

        let remoteTarget: BaoT3GranterConfig
        if let sshHost = opts["ssh-host"], !sshHost.isEmpty {
            remoteTarget = BaoT3GranterConfig(
                name: opts["ssh-name"] ?? sshHost,
                host: sshHost,
                port: Int(opts["ssh-port"] ?? "22") ?? 22,
                user: opts["ssh-user"] ?? "granter",
                hostKey: opts["ssh-host-key"] ?? ""
            )
        } else {
            remoteTarget = BaoT3GranterConfig(name: "", host: "")
        }

        let profile = BaoProfile(
            version: 1,
            name: name,
            openbao: BaoOpenBaoConfig(
                address: addr,
                namespace: namespace,
                caPEM: caPEM,
                mtlsClientIdentity: mtlsIdentity,
                jwtAuth: BaoJWTAuthConfig(
                    mount: mount,
                    role: role,
                    issuer: issuer,
                    audience: audience,
                    subject: subject
                ),
                tokenRoles: BaoTokenRolesConfig(mac: tokenRole, t3: tokenRole),
                grantPolicies: grantPolicies,
                auditPolicy: auditPolicy,
                maxHours: maxHours,
                keys: [],
                ssh: BaoSSHConfig(role: "", hosts: []),
                githubAppItem: "",
                githubTokenPath: opts["github-token-path"] ?? ""
            ),
            t3Granter: remoteTarget
        )
        try profile.validate()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(profile)
        guard let jsonText = String(data: data, encoding: .utf8) else {
            throw OpenBaoError.unexpectedResponse("failed to encode profile JSON")
        }

        if opts["save"] != nil {
            let saved = try BaoBuddyHelperCLI.upsertProfile(profile)
            fputs("Saved BaoBuddy profile '\(saved.displayName)' (\(saved.openbao.address))\n", stderr)
        }
        if opts["copy"] != nil, ManagedAppConfig.load().disableClipboard {
            fputs("Clipboard copy is disabled by your organization's MDM policy.\n", stderr)
        } else if opts["copy"] != nil {
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(jsonText, forType: .string)
            fputs("Copied profile JSON to clipboard (paste it in BaoBuddy on your iPhone).\n", stderr)
        }
        if opts["qr"] != nil {
            let uri = try ProfileTransferCodec.encodeURI(profile)
            if let ascii = MacQRCode.renderTerminalASCII(from: uri) {
                fputs("\nScan with BaoBuddy on your iPhone (or the iPhone Camera app):\n\n\(ascii)\n\n", stderr)
            }
        }
        print(jsonText)
    }

    /// Generates a variablized `for_each` OpenTofu / Terraform project (`bao-buddy tofu-init`).
    static func runTofuInit(args: [String], deviceName: String = "mac") throws {
        let opts = BaoBuddyHelperCLI.parseFlags(args)
        let includeSelf = opts["include-self"] != nil || opts["from-profile"] != nil

        let spec: BaoTofuDeploymentSpec
        if opts["from-profile"] != nil {
            let selector = opts["from-profile"] == "1" ? opts["profile"] : opts["from-profile"]
            let profile = try BaoBuddyHelperCLI.loadActiveProfile(selector: selector)
            let macPEM = includeSelf
                ? ((try? SecureEnclaveKeyStore.resolve(for: profile, deviceName: deviceName).publicKeyPEM()) ?? "")
                : ""
            var seeded = BaoTofuDeploymentSpec.from(profile: profile, devicePEM: macPEM)
            if let extraUsers = opts["users"], !extraUsers.isEmpty {
                let names = splitCSV(extraUsers)
                let policies = seeded.users.first?.allowedPolicies ?? ["read"]
                let maxH = seeded.users.first?.maxHours ?? profile.openbao.maxHours
                let cidrs = splitCSV(opts["cidrs"])
                seeded.users = names.enumerated().map { idx, name in
                    BaoTofuUserSpec(
                        name: name,
                        mount: "jwt-\(name)",
                        subject: name,
                        devicePublicKeysPEM: (idx == 0 && !macPEM.isEmpty) ? [macPEM] : [],
                        allowedPolicies: policies,
                        maxHours: maxH,
                        boundCIDRs: cidrs
                    )
                }
            }
            if let otlp = opts["otlp"], !otlp.isEmpty { seeded.otlpEndpoint = otlp }
            spec = seeded
        } else {
            let env = ProcessInfo.processInfo.environment
            let addr = opts["addr"] ?? env["BAO_ADDR"] ?? env["VAULT_ADDR"] ?? "https://openbao.example.com:8200"
            let name = opts["name"] ?? URL(string: addr)?.host ?? "OpenBao"
            let namespace = resolveNamespace(opts: opts)
            let caPEM = try resolveCAPEM(opts: opts)
            let mtlsIdentity = opts["mtls-identity"] ?? ""
            let userNames = splitCSV(opts["users"])
            let effectiveUsers = userNames.isEmpty ? [env["USER"] ?? "operator"] : userNames
            let policies = splitCSV(opts["policies"])
            let effectivePolicies = policies.isEmpty ? ["db-readonly", "k8s-deploy"] : policies
            let elevated = splitCSV(opts["elevated"])
            let cidrs = splitCSV(opts["cidrs"])
            let maxHours = Int(opts["max-hours"] ?? "12") ?? 12

            let users = effectiveUsers.enumerated().map { idx, user in
                let mount = "jwt-\(user)"
                let userPEM = (idx == 0 && includeSelf)
                    ? ((try? SecureEnclaveKeyStore.scoped(
                        address: addr,
                        namespace: namespace,
                        mount: mount,
                        caPEM: caPEM,
                        mtlsClientIdentity: mtlsIdentity,
                        deviceName: deviceName
                    ).publicKeyPEM()) ?? "")
                    : ""
                return BaoTofuUserSpec(
                    name: user,
                    mount: mount,
                    subject: user,
                    devicePublicKeysPEM: userPEM.isEmpty ? [] : [userPEM],
                    allowedPolicies: effectivePolicies,
                    maxHours: maxHours,
                    boundCIDRs: cidrs
                )
            }
            spec = BaoTofuDeploymentSpec(
                serverName: name,
                openbaoAddress: addr,
                namespace: namespace,
                caPEM: caPEM,
                mtlsClientIdentity: mtlsIdentity,
                audience: opts["audience"] ?? "",
                users: users,
                elevatedPolicies: elevated,
                auditPolicy: BaoAuditPolicy(
                    requireReason: opts["require-reason"] != nil,
                    requireReasonForElevated: opts["require-reason-elevated"] != nil,
                    reasonPattern: opts["reason-pattern"] ?? "",
                    reasonPlaceholder: opts["reason-placeholder"] ?? ""
                ),
                sshSignPath: opts["ssh-sign-path"] ?? "",
                githubTokenPath: opts["github-token-path"] ?? "",
                otlpEndpoint: opts["otlp"] ?? ""
            )
        }

        let outDir = opts["out"] ?? "./baobuddy-tofu"
        let url = URL(fileURLWithPath: outDir, isDirectory: true)
        let files = try BaoTofuBuilder.write(spec, to: url)
        print("Generated OpenTofu deployment in \(url.path):")
        for file in files {
            print("  - \(file)")
        }
        print("\nNext: cd \(outDir) && tofu init && tofu plan")
    }

    // MARK: - Helpers

    private struct AdminClientContext {
        let client: OpenBaoClient
        let token: String
        let caPEM: String
        let caCertPath: String
        let mtlsIdentity: String
    }

    private static func makeAdminClient(opts: [String: String]) throws -> AdminClientContext {
        let addr = try resolveAddress(opts: opts)
        let caCertPath = resolveCACertPath(opts: opts)
        let caPEM = try resolveCAPEM(opts: opts)
        let namespace = resolveNamespace(opts: opts)
        let mtlsIdentity = opts["mtls-identity"] ?? ""
        let client = try BaoServerAdmin.makeValidatedClient(
            address: addr,
            namespace: namespace,
            caPEM: caPEM,
            mtlsClientIdentity: mtlsIdentity,
            enforceTLSPinning: ManagedAppConfig.load().enforceTLSPinning
        )
        guard let token = try resolveOptionalToken(opts: opts), !token.isEmpty else {
            throw OpenBaoError.unexpectedResponse(
                "Set BAO_TOKEN / VAULT_TOKEN, or pipe the admin token in with --token-stdin."
            )
        }
        return AdminClientContext(
            client: client,
            token: token,
            caPEM: caPEM,
            caCertPath: caCertPath,
            mtlsIdentity: mtlsIdentity
        )
    }

    private static func resolveNamespace(opts: [String: String]) -> String {
        let env = ProcessInfo.processInfo.environment
        let raw = opts["namespace"] ?? env["BAO_NAMESPACE"] ?? env["VAULT_NAMESPACE"] ?? ""
        return raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func resolveAddress(opts: [String: String]) throws -> String {
        let env = ProcessInfo.processInfo.environment
        let addr = opts["addr"] ?? env["BAO_ADDR"] ?? env["VAULT_ADDR"] ?? ""
        let trimmed = addr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw OpenBaoError.invalidBaseURL("Set BAO_ADDR / VAULT_ADDR (or pass --addr https://...)")
        }
        return trimmed
    }

    /// The admin token comes from the environment or stdin, never a command-line flag, because
    /// arguments are visible to other processes (`ps`) and land in shell history.
    private static func resolveOptionalToken(opts: [String: String]) throws -> String? {
        if opts["token"] != nil {
            throw OpenBaoError.unexpectedResponse(
                "--token is not supported because arguments show up in `ps` and shell history; use BAO_TOKEN or --token-stdin"
            )
        }
        let raw: String?
        if opts["token-stdin"] != nil {
            raw = readLine(strippingNewline: true)
        } else {
            let env = ProcessInfo.processInfo.environment
            raw = env["BAO_TOKEN"] ?? env["VAULT_TOKEN"]
        }
        let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }

    private static func resolveCACertPath(opts: [String: String]) -> String {
        let env = ProcessInfo.processInfo.environment
        let raw = opts["cacert"] ?? env["BAO_CACERT"] ?? env["VAULT_CACERT"] ?? ""
        return raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func resolveCAPEM(opts: [String: String]) throws -> String {
        let path = resolveCACertPath(opts: opts)
        guard !path.isEmpty else {
            return ""
        }
        return try String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func splitCSV(_ raw: String?) -> [String] {
        guard let raw else { return [] }
        return raw.split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
}
#endif
