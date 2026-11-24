#if os(macOS)
import AppKit
import BaoBuddyCore
import SwiftUI

/// Dedicated resizable macOS window for the OpenTofu / Terraform Deployment Builder
/// so it never feels cramped inside the Settings sheet bounds.
@MainActor
final class MacTofuWindowController {
    static let shared = MacTofuWindowController()
    private var window: NSWindow?

    func show(profile: BaoProfile?, macPublicKeyPEM: String) {
        let rootView = MacTofuBuilderView(
            profile: profile,
            macPublicKeyPEM: macPublicKeyPEM,
            onClose: { [weak self] in
                self?.window?.close()
            }
        )
        if let window {
            window.contentViewController = NSHostingController(rootView: rootView)
            NSApp.activate()
            window.makeKeyAndOrderFront(nil)
            return
        }
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1280, height: 840),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        win.title = "OpenTofu / Terraform Deployment Builder"
        win.minSize = NSSize(width: 1060, height: 680)
        win.isReleasedWhenClosed = false
        win.contentViewController = NSHostingController(rootView: rootView)
        win.center()
        self.window = win
        NSApp.activate()
        win.makeKeyAndOrderFront(nil)
    }
}

/// Interactive macOS OpenTofu / Terraform deployment generator matching `bao-buddy tofu-init`.
struct MacTofuBuilderView: View {
    let onClose: () -> Void

    @State private var serverName: String
    @State private var openbaoAddress: String
    @State private var namespace: String
    @State private var otlpEndpoint: String
    @State private var sshSignPath: String
    @State private var githubTokenPath: String
    @State private var extensionPolicies: [BaoTofuExtensionPolicy]
    @State private var newExtPolicyName: String = ""
    @State private var newExtPath: String = ""
    @State private var newExtMethod: BaoExtensionMethod = .post
    @State private var showDirectEnginePaths: Bool = false

    @State private var usersCSV: String
    @State private var policiesCSV: String
    @State private var elevatedCSV: String
    @State private var cidrsCSV: String
    @State private var maxHours: Int
    @State private var includeMacKey: Bool
    @State private var requireReasonElevated: Bool
    @State private var reasonPattern: String

    @State private var selectedPreviewFile: String = "terraform.tfvars"
    @State private var statusMessage: String?
    @State private var statusIsError: Bool = false
    @State private var copiedFile: Bool = false

    private let macPublicKeyPEM: String
    private let previewOrder = ["terraform.tfvars", "main.tf", "variables.tf", "outputs.tf", "versions.tf", "README.md"]

    init(profile: BaoProfile?, macPublicKeyPEM: String, onClose: @escaping () -> Void) {
        self.macPublicKeyPEM = macPublicKeyPEM
        self.onClose = onClose
        if let profile {
            let seeded = BaoTofuDeploymentSpec.from(profile: profile, devicePEM: macPublicKeyPEM)
            self._serverName = State(initialValue: seeded.serverName)
            self._openbaoAddress = State(initialValue: seeded.openbaoAddress)
            self._namespace = State(initialValue: seeded.namespace)
            self._otlpEndpoint = State(initialValue: seeded.otlpEndpoint)
            self._sshSignPath = State(initialValue: seeded.sshSignPath)
            self._githubTokenPath = State(initialValue: seeded.githubTokenPath)
            self._showDirectEnginePaths = State(initialValue: !seeded.sshSignPath.isEmpty || !seeded.githubTokenPath.isEmpty)
            self._usersCSV = State(initialValue: seeded.users.map(\.name).joined(separator: ", "))
            let extNames = Set(seeded.extensionPolicies.map(\.name))
            let basePolicies = (seeded.users.first?.allowedPolicies ?? ["app-read"]).filter { !extNames.contains($0) }
            self._policiesCSV = State(initialValue: (basePolicies.isEmpty ? ["app-read"] : basePolicies).joined(separator: ", "))
            self._elevatedCSV = State(initialValue: seeded.elevatedPolicies.joined(separator: ", "))
            self._cidrsCSV = State(initialValue: (seeded.users.first?.boundCIDRs ?? []).joined(separator: ", "))
            self._maxHours = State(initialValue: seeded.users.first?.maxHours ?? 12)
            self._includeMacKey = State(initialValue: !macPublicKeyPEM.isEmpty)
            self._requireReasonElevated = State(initialValue: seeded.auditPolicy.requireReasonForElevated)
            self._reasonPattern = State(initialValue: seeded.auditPolicy.reasonPattern)
            self._extensionPolicies = State(initialValue: seeded.extensionPolicies)
        } else {
            let currentUser = ProcessInfo.processInfo.environment["USER"] ?? "operator"
            self._serverName = State(initialValue: "OpenBao")
            self._openbaoAddress = State(initialValue: "https://openbao.example.com:8200")
            self._namespace = State(initialValue: "")
            self._otlpEndpoint = State(initialValue: "")
            self._sshSignPath = State(initialValue: "")
            self._githubTokenPath = State(initialValue: "")
            self._usersCSV = State(initialValue: currentUser)
            self._policiesCSV = State(initialValue: "db-readonly, k8s-deploy")
            self._elevatedCSV = State(initialValue: "k8s-deploy")
            self._cidrsCSV = State(initialValue: "")
            self._maxHours = State(initialValue: 8)
            self._includeMacKey = State(initialValue: !macPublicKeyPEM.isEmpty)
            self._requireReasonElevated = State(initialValue: true)
            self._reasonPattern = State(initialValue: "")
            self._extensionPolicies = State(initialValue: [])
        }
    }

    private var generatedFiles: [String: String] {
        BaoTofuBuilder.generate(currentSpec())
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            HSplitView {
                configForm
                    .frame(minWidth: 420, idealWidth: 460, maxWidth: 520)
                previewPane
                    .frame(minWidth: 620, idealWidth: 820)
            }

            Divider()
            footer
        }
        .frame(minWidth: 1060, minHeight: 680)
    }

    private var header: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(MacBaoTheme.brand.gradient)
                .frame(width: 36, height: 36)
                .overlay {
                    Image(systemName: "cube.transparent.fill")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(MacBaoTheme.cream)
                }
            VStack(alignment: .leading, spacing: 2) {
                Text("OpenTofu / Terraform Deployment Builder")
                    .font(.headline)
                Text("Generates a variablized `for_each` OpenTofu stack with isolated per-operator JWT mounts, policies, credential extensions, and profile outputs.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
        .background(.bar)
    }

    private var configForm: some View {
        Form {
            Section("Server") {
                TextField("Server Name", text: $serverName, prompt: Text("Production"))
                TextField("Address", text: $openbaoAddress, prompt: Text(verbatim: "https://vault.example.com:8200"))
                TextField("Namespace", text: $namespace, prompt: Text("Optional (e.g. admin/prod)"))
                Stepper("Max TTL: \(maxHours) \(maxHours == 1 ? "hour" : "hours")", value: $maxHours, in: 1...24)
            }

            Section("Operators & Policies") {
                TextField("Operators (CSV)", text: $usersCSV, prompt: Text("alice, bob"))
                TextField("Allowed Policies", text: $policiesCSV, prompt: Text("db-readonly, k8s-deploy"))
                TextField("Elevated Policies", text: $elevatedCSV, prompt: Text("k8s-deploy"))
                TextField("Bound CIDRs", text: $cidrsCSV, prompt: Text("Optional (e.g. 10.0.0.0/8)"))
                if !macPublicKeyPEM.isEmpty {
                    Toggle("Embed this Mac's Secure Enclave key", isOn: $includeMacKey)
                        .tint(MacBaoTheme.brand)
                }
            }

            Section("Credential Extensions") {
                HStack(spacing: 8) {
                    Text("Generates dedicated least-privilege OpenBao ACL policies for dynamic secrets engines and adds them to each operator's `allowed_policies`.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer(minLength: 8)
                    Menu {
                        ForEach(BaoCredentialExtension.builtInTemplates) { template in
                            Button {
                                addTemplateExtension(template)
                            } label: {
                                Label(template.label, systemImage: template.icon)
                            }
                        }
                    } label: {
                        Label("Add Template", systemImage: "plus.circle")
                    }
                    .menuStyle(.button)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .fixedSize()
                }

                if extensionPolicies.isEmpty {
                    Text("No extension policies added yet. Choose a template (AWS STS, Kubernetes, Database, PKI, GitHub) or define a custom path below.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                } else {
                    ForEach(extensionPolicies, id: \.name) { extPolicy in
                        HStack(spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(extPolicy.name)
                                        .font(.caption.weight(.semibold).monospaced())
                                    Text(extPolicy.capabilities.joined(separator: ", "))
                                        .font(.caption2.monospaced())
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 1)
                                        .background(MacBaoTheme.brand.opacity(0.14), in: Capsule())
                                        .foregroundStyle(MacBaoTheme.brand)
                                }
                                Text(extPolicy.path)
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(role: .destructive) {
                                extensionPolicies.removeAll { $0.name == extPolicy.name }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.borderless)
                            .help("Remove extension policy")
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        TextField("Policy Name", text: $newExtPolicyName, prompt: Text("ext-aws-sts"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                        Picker("Method", selection: $newExtMethod) {
                            Text("POST").tag(BaoExtensionMethod.post)
                            Text("GET").tag(BaoExtensionMethod.get)
                        }
                        .labelsHidden()
                        .frame(width: 76)
                    }
                    HStack(spacing: 6) {
                        TextField("Secrets Path", text: $newExtPath, prompt: Text("aws/sts/deploy"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                        Button("Add") {
                            addCustomExtensionPolicy()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .fixedSize()
                        .disabled(
                            newExtPolicyName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                            newExtPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        )
                    }
                }
                .padding(.top, 2)
            }

            Section("Governance & Telemetry") {
                Toggle("Require reason on elevated grants", isOn: $requireReasonElevated)
                    .tint(MacBaoTheme.brand)
                TextField("Ticket Regex", text: $reasonPattern, prompt: Text(verbatim: "^(INC|CHG|JIRA)-[0-9]+"))
                TextField("OTLP Endpoint", text: $otlpEndpoint, prompt: Text(verbatim: "https://otel.example:4318"))

                DisclosureGroup("Direct Granter Paths (SSH / GitHub)", isExpanded: $showDirectEnginePaths) {
                    TextField("SSH CA Sign Path", text: $sshSignPath, prompt: Text("ssh/sign/ops"))
                    TextField("GitHub Token Path", text: $githubTokenPath, prompt: Text("github/token/push"))
                    Text("Grants the 2-minute granter policy direct access to sign SSH certificates or mint server-side GitHub tokens.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
    }

    private var previewPane: some View {
        let content = generatedFiles[selectedPreviewFile] ?? ""
        let lines = content.split(separator: "\n", omittingEmptySubsequences: false)
        let highlighted = MacCodeHighlighter.highlight(content, fileName: selectedPreviewFile)

        return VStack(spacing: 0) {
            HStack(spacing: 8) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 4) {
                        ForEach(previewOrder, id: \.self) { file in
                            let isSelected = selectedPreviewFile == file
                            Button {
                                selectedPreviewFile = file
                            } label: {
                                Text(file)
                                    .font(.caption.weight(isSelected ? .semibold : .medium).monospaced())
                                    .padding(.horizontal, 9)
                                    .padding(.vertical, 5)
                                    .background(
                                        isSelected ? MacBaoTheme.brand.opacity(0.18) : Color.clear,
                                        in: RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    )
                                    .foregroundStyle(isSelected ? MacBaoTheme.brand : .secondary)
                                    .contentShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                Text("\(lines.count) lines")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.tertiary)
                    .fixedSize()

                Button {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(content, forType: .string)
                    copiedFile = true
                    Task {
                        try? await Task.sleep(for: .seconds(2))
                        copiedFile = false
                    }
                } label: {
                    Label(
                        copiedFile ? "Copied" : "Copy File",
                        systemImage: copiedFile ? "checkmark" : "doc.on.doc"
                    )
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .tint(copiedFile ? MacBaoTheme.active : nil)
                .fixedSize()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(.bar)

            Divider()

            ScrollView([.horizontal, .vertical]) {
                HStack(alignment: .top, spacing: 14) {
                    Text((1...max(1, lines.count)).map(String.init).joined(separator: "\n"))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.trailing)
                        .lineSpacing(3)
                        .frame(minWidth: 28, alignment: .trailing)

                    Text(highlighted)
                        .font(.system(size: 12, design: .monospaced))
                        .multilineTextAlignment(.leading)
                        .lineSpacing(3)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(16)
            }
            .background(Color(nsColor: .textBackgroundColor).opacity(0.65))
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            Button("Close") { onClose() }
                .keyboardShortcut(.cancelAction)

            if let statusMessage {
                Label(statusMessage, systemImage: statusIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(statusIsError ? .red : MacBaoTheme.active)
                    .lineLimit(1)
            }

            Spacer()

            Button {
                exportFolder()
            } label: {
                Label("Export OpenTofu Folder…", systemImage: "folder.badge.plus")
            }
            .buttonStyle(.borderedProminent)
            .tint(MacBaoTheme.brand)
            .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
        .background(.bar)
    }

    private func addTemplateExtension(_ template: BaoCredentialExtension) {
        let policyName = template.policy.isEmpty ? "ext-\(template.id)" : template.policy
        let caps = template.method == .get ? ["read"] : ["create", "update"]
        let item = BaoTofuExtensionPolicy(name: policyName, path: template.endpoint, capabilities: caps)
        if let idx = extensionPolicies.firstIndex(where: { $0.name == policyName }) {
            extensionPolicies[idx] = item
        } else {
            extensionPolicies.append(item)
        }
        selectedPreviewFile = "terraform.tfvars"
    }

    private func addCustomExtensionPolicy() {
        let name = newExtPolicyName.trimmingCharacters(in: .whitespacesAndNewlines)
        let path = newExtPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !path.isEmpty else { return }
        let caps = newExtMethod == .get ? ["read"] : ["create", "update"]
        let item = BaoTofuExtensionPolicy(name: name, path: path, capabilities: caps)
        if let idx = extensionPolicies.firstIndex(where: { $0.name == name }) {
            extensionPolicies[idx] = item
        } else {
            extensionPolicies.append(item)
        }
        newExtPolicyName = ""
        newExtPath = ""
        selectedPreviewFile = "terraform.tfvars"
    }

    private func currentSpec() -> BaoTofuDeploymentSpec {
        let userNames = splitCSV(usersCSV)
        let effectiveUsers = userNames.isEmpty ? ["operator"] : userNames
        let basePolicies = splitCSV(policiesCSV)
        let extPolicyNames = extensionPolicies.map(\.name)
        var mergedPolicies = basePolicies.isEmpty ? ["app-read"] : basePolicies
        for name in extPolicyNames where !mergedPolicies.contains(name) {
            mergedPolicies.append(name)
        }
        let elevated = splitCSV(elevatedCSV)
        let cidrs = splitCSV(cidrsCSV)

        let userSpecs = effectiveUsers.enumerated().map { idx, name in
            BaoTofuUserSpec(
                name: name,
                mount: "jwt-\(name)",
                subject: name,
                devicePublicKeysPEM: (idx == 0 && includeMacKey && !macPublicKeyPEM.isEmpty) ? [macPublicKeyPEM] : [],
                allowedPolicies: mergedPolicies,
                maxHours: maxHours,
                boundCIDRs: cidrs
            )
        }

        let trimmedServer = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        return BaoTofuDeploymentSpec(
            serverName: trimmedServer.isEmpty ? "OpenBao" : trimmedServer,
            openbaoAddress: openbaoAddress.trimmingCharacters(in: .whitespacesAndNewlines),
            namespace: namespace.trimmingCharacters(in: .whitespacesAndNewlines),
            users: userSpecs,
            elevatedPolicies: elevated,
            auditPolicy: BaoAuditPolicy(
                requireReason: false,
                requireReasonForElevated: requireReasonElevated,
                reasonPattern: reasonPattern.trimmingCharacters(in: .whitespacesAndNewlines)
            ),
            sshSignPath: sshSignPath.trimmingCharacters(in: .whitespacesAndNewlines),
            githubTokenPath: githubTokenPath.trimmingCharacters(in: .whitespacesAndNewlines),
            otlpEndpoint: otlpEndpoint.trimmingCharacters(in: .whitespacesAndNewlines),
            extensionPolicies: extensionPolicies
        )
    }

    private func exportFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Export OpenTofu Files Here"
        panel.message = "Choose a folder to write versions.tf, variables.tf, main.tf, outputs.tf, and terraform.tfvars"
        guard panel.runModal() == .OK, let dir = panel.url else { return }
        do {
            let written = try BaoTofuBuilder.write(currentSpec(), to: dir)
            statusIsError = false
            statusMessage = "Wrote \(written.count) files to \(dir.lastPathComponent)/"
            NSWorkspace.shared.activateFileViewerSelecting([dir])
        } catch {
            statusIsError = true
            statusMessage = error.localizedDescription
        }
    }

    private func splitCSV(_ text: String) -> [String] {
        text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
}
#endif
