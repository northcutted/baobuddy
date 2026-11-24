import BaoBuddyCore
import SwiftUI

/// Form-based server & dynamic policy editor so any OpenBao or HashiCorp Vault user
/// can add multiple targets and define their own custom policies with zero scripting.
struct ManualProfileSheetView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss

    private let existingID: String?
    private let existingKeys: [BaoKeyItem]
    private let existingSSH: BaoSSHConfig
    private let existingGitHubAppItem: String
    private let existingGitHubTokenPath: String
    private let existingPolicyConfig: BaoPolicyConfig?
    /// The profile being edited, so settings this form doesn't show (telemetry, extensions,
    /// extra remote targets) are kept rather than silently dropped on save.
    private let existingProfile: BaoProfile?

    @State private var profileName: String
    @State private var address: String
    @State private var namespace: String
    @State private var caPEM: String
    @State private var mtlsClientIdentity: String
    @State private var jwtMount: String
    @State private var jwtRole: String
    @State private var jwtIssuer: String
    @State private var jwtAudience: String
    @State private var jwtSubject: String
    @State private var localTokenRole: String
    @State private var remoteTokenRole: String
    @State private var maxHours: Int

    @State private var requireReason: Bool
    @State private var requireReasonForElevated: Bool
    @State private var reasonPattern: String
    @State private var reasonPlaceholder: String

    @State private var extensions: [BaoCredentialExtension]
    @State private var newExtID: String = ""
    @State private var newExtLabel: String = ""
    @State private var newExtEndpoint: String = ""
    @State private var newExtPolicy: String = ""
    @State private var newExtDeliverAs: String = ""
    @State private var newExtMethod: BaoExtensionMethod = .post
    @State private var newExtElevated: Bool = false

    @State private var useCustomPolicies: Bool
    @State private var readPolicy: String
    @State private var writePolicy: String
    @State private var customPolicies: [BaoBuddyPolicy]

    // Inline add-policy draft fields
    @State private var newPolicyName: String = ""
    @State private var newPolicyLabel: String = ""
    @State private var newPolicyDesc: String = ""
    @State private var newPolicyElevated: Bool = false
    @State private var newPolicyDefault: Bool = false

    @State private var enableRemoteTarget: Bool
    @State private var remoteName: String
    @State private var remoteHost: String
    @State private var remotePort: String
    @State private var remoteUser: String
    @State private var remoteHostKey: String

    @State private var validationError: String?

    init(model: AppModel, existing: BaoProfile?) {
        self.model = model
        self.existingID = existing?.id
        self.existingKeys = existing?.openbao.keys ?? []
        self.existingSSH = existing?.openbao.ssh ?? BaoSSHConfig(role: "", hosts: [])
        self.existingGitHubAppItem = existing?.openbao.githubAppItem ?? ""
        self.existingGitHubTokenPath = existing?.openbao.githubTokenPath ?? ""
        self.existingPolicyConfig = existing?.openbao.policies
        self.existingProfile = existing

        self._profileName = State(initialValue: existing?.name ?? "")
        self._address = State(initialValue: existing?.openbao.address ?? "https://")
        self._namespace = State(initialValue: existing?.openbao.namespace ?? "")
        self._caPEM = State(initialValue: existing?.openbao.caPEM ?? "")
        self._mtlsClientIdentity = State(initialValue: existing?.openbao.mtlsClientIdentity ?? "")
        self._jwtMount = State(initialValue: existing?.openbao.jwtAuth.mount ?? "jwt-user")
        self._jwtRole = State(initialValue: existing?.openbao.jwtAuth.role ?? "granter")
        self._jwtIssuer = State(initialValue: existing?.openbao.jwtAuth.issuer ?? "bao-granter")
        self._jwtAudience = State(initialValue: existing?.openbao.jwtAuth.audience ?? "")
        self._jwtSubject = State(initialValue: existing?.openbao.jwtAuth.subject ?? "")
        self._localTokenRole = State(initialValue: existing?.openbao.tokenRoles.mac ?? "")
        self._remoteTokenRole = State(initialValue: existing?.openbao.tokenRoles.t3 ?? "")
        self._maxHours = State(initialValue: existing?.openbao.maxHours ?? 12)

        let audit = existing?.openbao.auditPolicy ?? .none
        self._requireReason = State(initialValue: audit.requireReason)
        self._requireReasonForElevated = State(initialValue: audit.requireReasonForElevated)
        self._reasonPattern = State(initialValue: audit.reasonPattern)
        self._reasonPlaceholder = State(initialValue: audit.reasonPlaceholder)
        self._extensions = State(initialValue: existing?.openbao.extensions ?? [])

        let hasCustom = existing?.openbao.usesCustomPolicies ?? (existing == nil)
        self._useCustomPolicies = State(initialValue: hasCustom)
        self._readPolicy = State(initialValue: existing?.openbao.policies.read ?? "read")
        self._writePolicy = State(initialValue: existing?.openbao.policies.write ?? "write")
        self._customPolicies = State(initialValue: existing?.openbao.grantPolicies ?? [])

        self._enableRemoteTarget = State(initialValue: existing?.hasRemoteTarget ?? false)
        self._remoteName = State(
            initialValue: existing?.t3Granter.name.isEmpty == false
                ? (existing?.t3Granter.name ?? "")
                : String(localized: "Remote Host", comment: "Default name for a new remote SSH host that receives grants; the user can edit it.")
        )
        self._remoteHost = State(initialValue: existing?.t3Granter.host ?? "")
        self._remotePort = State(initialValue: String(existing?.t3Granter.port ?? 22))
        self._remoteUser = State(initialValue: existing?.t3Granter.user ?? "granter")
        self._remoteHostKey = State(initialValue: existing?.t3Granter.hostKey ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                if let validationError {
                    Section {
                        Text(validationError)
                            .foregroundStyle(.red)
                    }
                }

                Section("Server") {
                    BaoTextField("Display Name (e.g. Production OpenBao)", text: $profileName)
                    BaoTextField("Address", text: $address, prompt: "https://openbao.example.com:8200")
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    BaoTextField("Namespace (optional, e.g. admin/prod)", text: $namespace)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Stepper("Max Grant TTL: \(maxHours)h", value: $maxHours, in: 1...24)
                }

                Section("JWT Auth Mount (ES256)") {
                    BaoTextField("Auth Mount (e.g. jwt-granter)", text: $jwtMount)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    BaoTextField("JWT Role", text: $jwtRole)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    BaoTextField("Bound Subject (sub)", text: $jwtSubject)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    BaoTextField("Bound Issuer (iss)", text: $jwtIssuer)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    BaoTextField("Bound Audience (aud)", text: $jwtAudience)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    BaoTextField("Token Role (auth/token/create/<role>)", text: $localTokenRole)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section {
                    Picker("Policy Model", selection: $useCustomPolicies) {
                        Text("Custom Policies").tag(true)
                        Text("Read / Write").tag(false)
                    }
                    .baoSegmentedPicker()

                    if useCustomPolicies {
                        ForEach(customPolicies) { policy in
                            VStack(alignment: .leading, spacing: 3) {
                                HStack {
                                    Text(policy.displayLabel)
                                        .font(.subheadline.weight(.medium))
                                    Spacer()
                                    if policy.elevated {
                                        Text("Elevated")
                                            .baoCaption2Font(.semibold)
                                            .foregroundStyle(BaoTheme.elevated)
                                    }
                                    if policy.defaultSelected {
                                        Text("Default")
                                            .baoCaption2Font(.semibold)
                                            .foregroundStyle(BaoTheme.brand)
                                    }
                                }
                                Text(policy.name)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                if !policy.description.isEmpty {
                                    Text(policy.description)
                                        .baoCaption2Font()
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .onDelete { offsets in
                            customPolicies.remove(atOffsets: offsets)
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            BaoTextField("OpenBao policy name (e.g. k8s-deploy)", text: $newPolicyName)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .font(.subheadline.monospaced())
                            BaoTextField("Display label (optional)", text: $newPolicyLabel)
                            BaoTextField("Short description (optional)", text: $newPolicyDesc)
                            Toggle("Elevated (highlights in orange)", isOn: $newPolicyElevated)
                            Toggle("Selected by default", isOn: $newPolicyDefault)
                            Button {
                                addPolicy()
                            } label: {
                                Label("Add Policy", systemImage: "plus.circle.fill")
                                    .frame(maxWidth: .infinity)
                            }
                            .disabled(newPolicyName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        }
                        .padding(.vertical, 4)
                    } else {
                        BaoTextField("Read Policy", text: $readPolicy)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        BaoTextField("Write Policy", text: $writePolicy)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                } header: {
                    Text("Policies")
                } footer: {
                    Text(
                        useCustomPolicies
                            ? "Each policy you add becomes an interactive toggle in the Grants tab and Approval sheet."
                            : "Standard read/write mode preserves any restricted keys and SSH hosts from imported profiles."
                    )
                }

                Section("Custom TLS Certificate / mTLS (Optional)") {
                    TextEditor(text: $caPEM)
                        .baoCaption2Font(monospaced: true)
                        .frame(minHeight: 90)
                        .accessibilityLabel("CA Certificate PEM")
                    BaoTextField("mTLS Client Cert CN or SHA-256 (optional)", text: $mtlsClientIdentity)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section("Audit & Change-Ticket Policy (Optional)") {
                    Toggle("Require reason on elevated grants", isOn: $requireReasonForElevated)
                    Toggle("Require reason on all grants", isOn: $requireReason)
                    BaoTextField("Ticket Regex (e.g. ^(INC|CHG)-[0-9]+)", text: $reasonPattern)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    BaoTextField("Reason prompt hint (optional)", text: $reasonPlaceholder)
                }

                Section {
                    Menu {
                        ForEach(BaoCredentialExtension.builtInTemplates) { template in
                            Button {
                                if !extensions.contains(where: { $0.id == template.id }) {
                                    extensions.append(template)
                                }
                            } label: {
                                Label(template.label, systemImage: template.icon)
                            }
                        }
                    } label: {
                        Label("Add Example Template…", systemImage: "puzzlepiece.extension")
                    }

                    ForEach($extensions) { $ext in
                        Toggle(isOn: $ext.enabled) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(ext.displayLabel)
                                    .font(.subheadline.weight(.medium))
                                Text(verbatim: "\(ext.method.rawValue) \(ext.endpoint) → \(ext.deliverAs)")
                                    .baoCaption2Font(monospaced: true)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .onDelete { offsets in
                        extensions.remove(atOffsets: offsets)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        BaoTextField("Extension ID (e.g. aws-sts)", text: $newExtID)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.subheadline.monospaced())
                        BaoTextField("Display label (e.g. AWS STS)", text: $newExtLabel)
                        BaoTextField("OpenBao endpoint (e.g. aws/sts/deploy)", text: $newExtEndpoint)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.subheadline.monospaced())
                        BaoTextField("OpenBao policy (optional)", text: $newExtPolicy)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.subheadline.monospaced())
                        BaoTextField("Filename (e.g. aws-creds.json)", text: $newExtDeliverAs)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(.subheadline.monospaced())
                        Picker("HTTP Method", selection: $newExtMethod) {
                            Text(verbatim: "POST").tag(BaoExtensionMethod.post)
                            Text(verbatim: "GET").tag(BaoExtensionMethod.get)
                        }
                        .baoSegmentedPicker()
                        Toggle("Elevated (highlights in orange)", isOn: $newExtElevated)
                        Button {
                            addExtension()
                        } label: {
                            Label("Add Extension", systemImage: "plus.circle.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .disabled(
                            newExtID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                            newExtEndpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        )
                    }
                    .padding(.vertical, 4)
                } header: {
                    Text("Credential Extensions (Optional)")
                } footer: {
                    Text("Invoke dynamic OpenBao secrets engines (AWS STS, Kubernetes, Database, PKI, GitHub) using the grant token.")
                }

                Section {
                    Toggle("Deliver Grants Over SSH", isOn: $enableRemoteTarget)
                    if enableRemoteTarget {
                        BaoTextField("Target Name (e.g. Bastion)", text: $remoteName)
                        BaoTextField("Host or IP", text: $remoteHost)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        BaoTextField("Port (22)", text: $remotePort)
                            .keyboardType(.numberPad)
                        BaoTextField("SSH User (granter)", text: $remoteUser)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        BaoTextField("Remote Token Role", text: $remoteTokenRole)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        BaoTextField("Pinned SSH Host Key (required, ssh-ed25519 AAAA...)", text: $remoteHostKey)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                } header: {
                    Text("Remote SSH Target (Optional)")
                } footer: {
                    Text("Leave off to mint scoped OpenBao/Vault tokens directly for copying to your clipboard.")
                }
            }
            .navigationTitle(existingID == nil ? "Add Server" : "Edit Server")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                }
            }
        }
    }

    private func addPolicy() {
        let name = newPolicyName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        let policy = BaoBuddyPolicy(
            name: name,
            label: newPolicyLabel.trimmingCharacters(in: .whitespacesAndNewlines),
            description: newPolicyDesc.trimmingCharacters(in: .whitespacesAndNewlines),
            elevated: newPolicyElevated,
            defaultSelected: newPolicyDefault
        )
        if let index = customPolicies.firstIndex(where: { $0.name == name }) {
            customPolicies[index] = policy
        } else {
            customPolicies.append(policy)
        }
        newPolicyName = ""
        newPolicyLabel = ""
        newPolicyDesc = ""
        newPolicyElevated = false
        newPolicyDefault = false
        BaoHaptics.impact()
    }

    private func addExtension() {
        let id = newExtID.trimmingCharacters(in: .whitespacesAndNewlines)
        let endpoint = newExtEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !endpoint.isEmpty else { return }
        let deliver = newExtDeliverAs.trimmingCharacters(in: .whitespacesAndNewlines)
        let ext = BaoCredentialExtension(
            id: id,
            label: newExtLabel.trimmingCharacters(in: .whitespacesAndNewlines),
            endpoint: endpoint,
            method: newExtMethod,
            deliverAs: deliver.isEmpty ? "\(id).json" : deliver,
            policy: newExtPolicy.trimmingCharacters(in: .whitespacesAndNewlines),
            elevated: newExtElevated,
            enabled: true
        )
        extensions.removeAll { $0.id == id }
        extensions.append(ext)
        newExtID = ""
        newExtLabel = ""
        newExtEndpoint = ""
        newExtPolicy = ""
        newExtDeliverAs = ""
        newExtElevated = false
        BaoHaptics.impact()
    }

    private func save() {
        let trimmedAddress = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmedAddress), url.scheme?.lowercased() == "https" || url.scheme?.lowercased() == "http" else {
            validationError = String(localized: "Enter a valid https:// OpenBao server URL.", comment: "Validation error. Keep https:// as is.")
            return
        }
        guard !jwtMount.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !jwtRole.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !jwtSubject.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            validationError = String(localized: "JWT mount, role, and subject are required.", comment: "Validation error. JWT mount, role and subject are fields on this form.")
            return
        }
        if useCustomPolicies && customPolicies.isEmpty {
            validationError = String(localized: "Add at least one custom policy, or switch to Read / Write mode.", comment: "Validation error. Read / Write is the name of a policy model option on this form.")
            return
        }

        let remote: BaoT3GranterConfig
        if enableRemoteTarget {
            let trimmedHost = remoteHost.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedHost.isEmpty else {
                validationError = String(localized: "Enter a remote SSH host or turn off SSH delivery.", comment: "Validation error.")
                return
            }
            remote = BaoT3GranterConfig(
                name: remoteName.trimmingCharacters(in: .whitespacesAndNewlines),
                host: trimmedHost,
                port: Int(remotePort) ?? 22,
                user: remoteUser.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? "granter"
                    : remoteUser.trimmingCharacters(in: .whitespacesAndNewlines),
                hostKey: remoteHostKey.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        } else {
            remote = BaoT3GranterConfig(name: "", host: "")
        }

        let trimmedNS = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedMount = jwtMount.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSubject = jwtSubject.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedCA = caPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedMTLS = mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines)
        let rawAudience = jwtAudience.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedAudience = rawAudience.isEmpty
            ? BaoOpenBaoConfig.defaultAudience(
                address: trimmedAddress,
                namespace: trimmedNS,
                mount: trimmedMount,
                caPEM: trimmedCA,
                mtlsClientIdentity: trimmedMTLS
            )
            : rawAudience
        let rawLocalRole = localTokenRole.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedLocalRole = rawLocalRole.isEmpty
            ? BaoServerAdmin.defaultTokenRole(mount: trimmedMount, subject: trimmedSubject)
            : rawLocalRole
        let rawRemoteRole = remoteTokenRole.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedRemoteRole = rawRemoteRole.isEmpty ? resolvedLocalRole : rawRemoteRole

        var newProfile = BaoProfile(
            id: existingID ?? UUID().uuidString.lowercased(),
            version: 1,
            name: profileName.trimmingCharacters(in: .whitespacesAndNewlines),
            openbao: BaoOpenBaoConfig(
                address: trimmedAddress,
                namespace: trimmedNS,
                caPEM: caPEM.trimmingCharacters(in: .whitespacesAndNewlines),
                mtlsClientIdentity: mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines),
                jwtAuth: BaoJWTAuthConfig(
                    mount: trimmedMount,
                    role: jwtRole.trimmingCharacters(in: .whitespacesAndNewlines),
                    issuer: jwtIssuer.trimmingCharacters(in: .whitespacesAndNewlines),
                    audience: resolvedAudience,
                    subject: trimmedSubject
                ),
                tokenRoles: BaoTokenRolesConfig(
                    mac: resolvedLocalRole,
                    t3: enableRemoteTarget ? resolvedRemoteRole : resolvedLocalRole
                ),
                // Keep the existing key prefix and suffix; resetting them to defaults would make the
                // Keys row describe different policies than the ones actually minted.
                policies: BaoPolicyConfig(
                    read: readPolicy.trimmingCharacters(in: .whitespacesAndNewlines),
                    write: writePolicy.trimmingCharacters(in: .whitespacesAndNewlines),
                    keyPrefix: existingPolicyConfig?.keyPrefix ?? "",
                    keyWriteSuffix: existingPolicyConfig?.keyWriteSuffix ?? ""
                ),
                grantPolicies: useCustomPolicies ? customPolicies : [],
                auditPolicy: BaoAuditPolicy(
                    requireReason: requireReason,
                    requireReasonForElevated: requireReasonForElevated,
                    reasonPattern: reasonPattern.trimmingCharacters(in: .whitespacesAndNewlines),
                    reasonPlaceholder: reasonPlaceholder.trimmingCharacters(in: .whitespacesAndNewlines)
                ),
                maxHours: maxHours,
                keys: existingKeys,
                ssh: existingSSH,
                githubAppItem: existingGitHubAppItem,
                githubTokenPath: existingGitHubTokenPath
            ),
            t3Granter: remote
        )

        if let existingProfile {
            newProfile.openbao.telemetry = existingProfile.openbao.telemetry
            if remote.isConfigured, existingProfile.remoteTargets.count > 1 {
                newProfile.remoteTargets = [remote] + existingProfile.remoteTargets.dropFirst()
            }
        }
        newProfile.openbao.extensions = extensions

        do {
            try model.upsertProfile(newProfile)
            dismiss()
        } catch {
            validationError = error.localizedDescription
        }
    }
}
