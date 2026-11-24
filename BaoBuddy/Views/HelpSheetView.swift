import BaoBuddyCore
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Native grouped Help & Setup Guide explaining what BaoBuddy is,
/// what is required on OpenBao / Vault, and common use cases.
struct HelpSheetView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var showSnippet: Bool = false
    @State private var copiedSnippet: Bool = false
    @State private var copiedDiagnostics: Bool = false

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"
    }

    private var appBuild: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
    }

    private var biometryText: String {
        model.biometry.nameInSentence
    }

    /// Stays in English: it's pasted into bug reports for the developer.
    private func diagnosticSummary() -> String {
        let jwtStatus = model.devicePublicKeyPEM.isEmpty ? "not set up" : "ready (Secure Enclave)"
        let sshStatus = model.sshPublicKey.isEmpty ? "not set up" : (model.sshKeyIsHardwareBacked ? "hardware (Secure Enclave)" : "software")
        return """
        BaoBuddy iOS \(appVersion) (build \(appBuild))
        OS: \(ProcessInfo.processInfo.operatingSystemVersionString)
        Servers configured: \(model.profiles.count)
        Approval key: \(jwtStatus)
        SSH delivery key: \(sshStatus)
        """
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 14) {
                        BaoBuddyEmblem(tint: BaoTheme.brand, size: 48)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(verbatim: "BaoBuddy")
                                .font(.headline)
                            Text("Biometric grants for OpenBao & HashiCorp Vault")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)

                    Text(
                        "BaoBuddy replaces passwords with a non-exportable EC P-256 key inside Apple's Secure Enclave. Each approval signs a 30-second ES256 JWT with \(biometryText), mints only the scoped short-lived token you chose, and immediately revokes its temporary sign-in token.",
                        comment: "Help screen. %@ is Face ID, Touch ID or the word biometrics. EC P-256, ES256, JWT and Secure Enclave are technical/product names."
                    )
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                }

                Section("What You Need to Set It Up") {
                    stepRow("1", "OpenBao or HashiCorp Vault Server", "Reachable over HTTPS or your private VPN/LAN. Self-signed and private CA certificates are supported via pinned PEM.")
                    stepRow("2", "Secure Enclave Key", "Create your EC P-256 key in Settings → Hardware Approval Key and copy its public key PEM.")
                    stepRow("3", "ES256 JWT Auth + Scoped Token Role", "Enable JWT auth trusting your PEM with a least-privilege granter policy that can only create scoped tokens.")
                    stepRow("4", "Server & Policies in Settings", "Import a JSON profile or add your server manually with custom policies. Add an SSH target only if you want remote delivery.")

                    DisclosureGroup("Example OpenBao CLI Setup", isExpanded: $showSnippet) {
                        Text(model.openBaoSetupSnippet())
                            .baoCaption2Font(monospaced: true)
                            .textSelection(.enabled)

                        Button {
                            #if canImport(UIKit)
                            UIPasteboard.general.string = model.openBaoSetupSnippet()
                            #endif
                            copiedSnippet = true
                            BaoHaptics.notify(.success)
                        } label: {
                            Label(
                                copiedSnippet ? "Copied Setup Commands" : "Copy Setup Commands",
                                systemImage: copiedSnippet ? "checkmark" : "doc.on.doc"
                            )
                        }
                    }
                }

                Section("Suggested Use Cases") {
                    useCaseRow("cpu", "AI Agents & Autonomous VMs", "Keep agents locked out of secrets and SSH by default; approve time-boxed grants from your phone via baobuddy:// links.")
                    useCaseRow("flame", "Break-Glass & Production Deploys", "Define custom policies like k8s-deploy, terraform-apply, or db-write and mint 1-hour audited tokens with \(biometryText).")
                    useCaseRow("terminal", "Ephemeral SSH Certificates", "Sign short-lived OpenBao SSH user certificates for bastions and servers instead of distributing permanent SSH keys.")
                    useCaseRow("server.rack", "Multi-Environment Operations", "Switch between Development, Staging, and Production servers with separate custom policy catalogs.")
                }

                Section("Security & Privacy") {
                    Label("Private signing keys never leave Apple's Secure Enclave.", systemImage: "lock.shield")
                    Label("No passwords, cloud sync, analytics, or third-party relays.", systemImage: "hand.raised")
                    Label("Every grant records an audit reason and expires automatically.", systemImage: "clock.badge.checkmark")
                    Label("Direct tokens copy to a 2-minute auto-expiring clipboard.", systemImage: "doc.on.clipboard")
                }
                .font(.subheadline)

                Section("Version & Support") {
                    LabeledContent("Version", value: "\(appVersion) (\(appBuild))")
                    if let repoURL = URL(string: "https://github.com/northcutted/baobuddy") {
                        Link(destination: repoURL) {
                            Label("Documentation & Source Code", systemImage: "book.closed")
                        }
                    }
                    if let issuesURL = URL(string: "https://github.com/northcutted/baobuddy/issues/new") {
                        Link(destination: issuesURL) {
                            Label("Report an Issue", systemImage: "ladybug")
                        }
                    }
                    Button {
                        #if canImport(UIKit)
                        UIPasteboard.general.string = diagnosticSummary()
                        #endif
                        copiedDiagnostics = true
                        BaoHaptics.notify(.success)
                    } label: {
                        Label(
                            copiedDiagnostics ? "Copied Diagnostics" : "Copy Diagnostics (No Secrets)",
                            systemImage: copiedDiagnostics ? "checkmark" : "doc.on.doc"
                        )
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("About BaoBuddy")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }

    private func stepRow(_ number: String, _ title: LocalizedStringKey, _ detail: LocalizedStringKey) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(verbatim: number)
                .font(.caption.weight(.bold).monospaced())
                .foregroundStyle(BaoTheme.brand)
                .frame(width: 22, height: 22)
                .background(BaoTheme.brand.opacity(0.14), in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.medium))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func useCaseRow(_ icon: String, _ title: LocalizedStringKey, _ detail: LocalizedStringKey) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(BaoTheme.brand)
                .frame(width: 22)
                .padding(.top, 2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.medium))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
