import BaoBuddyCore
import SwiftUI

struct ApprovalSheetView: View {
    @Bindable var model: AppModel
    let profile: BaoProfile
    let request: GrantRequest
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @ScaledMetric(relativeTo: .subheadline) private var iconColumnWidth: CGFloat = 18

    /// Capsules keep to one line, except at accessibility sizes, where they wrap rather than overflow.
    private var capsulesFit: Bool {
        !dynamicTypeSize.isAccessibilitySize
    }

    private var elevated: Bool {
        request.isElevated(profile: profile)
    }

    private var accent: Color {
        elevated ? BaoTheme.elevated : BaoTheme.brand
    }

    var body: some View {
        NavigationStack {
            List {
                // Clean native header section
                Section {
                    BaoAdaptiveStack(spacing: 14) {
                        BaoBuddyEmblem(tint: accent, size: 48)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(elevated ? "Elevated Grant" : "Standard Grant")
                                .font(.headline)
                            Text(profile.displayName)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("\(request.hours) hours", comment: "The grant's duration. %lld is a number of hours.")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(accent)
                    }
                    .padding(.vertical, 4)

                    if elevated {
                        Label(
                            "Includes permissions beyond read-only access. Verify the scope below before authenticating.",
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .font(.footnote)
                        .foregroundStyle(BaoTheme.elevated)
                    }
                }

                // Scope breakdown
                Section("Scope") {
                    LabeledContent(
                        "Target",
                        value: profile.hasRemoteTarget && request.target == .t3
                            ? profile.targetDisplayName
                            : String(localized: "Direct Token", comment: "Where a grant goes when it has no remote host: a token shown in this app.")
                    )

                    if !profile.openbao.namespace.isEmpty {
                        LabeledContent("Namespace") {
                            Text(profile.openbao.namespace)
                                .font(.footnote.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }

                    if profile.isDemoProfile {
                        Label("Simulated in-memory server — nothing leaves this device.", systemImage: "flask.fill")
                            .font(.footnote)
                            .foregroundStyle(BaoTheme.brand)
                    } else if !profile.openbao.isTLSPinned {
                        Label("TLS isn't pinned for \(profile.displayName)", systemImage: "lock.trianglebadge.exclamationmark")
                            .font(.footnote)
                            .foregroundStyle(BaoTheme.elevated)
                    }

                    if !request.customPolicies.isEmpty || profile.openbao.usesCustomPolicies {
                        let policyNames = request.openBaoPolicies(profile: profile)
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Policies")
                                .font(.subheadline)
                            ForEach(policyNames, id: \.self) { name in
                                let catalogLabel = profile.openbao.policyLabel(for: name)
                                let extLabel = profile.openbao.enabledExtensions.first(where: { $0.policy == name })?.displayLabel
                                let displayTitle: String = {
                                    if catalogLabel != name { return catalogLabel }
                                    if let extLabel, !extLabel.isEmpty { return extLabel }
                                    return String(localized: "Policy", comment: "Label for an OpenBao policy that has no display name. Shown next to the policy's name.")
                                }()
                                BaoAdaptiveStack(spacing: 8) {
                                    Text(displayTitle)
                                        .font(.subheadline)
                                        .foregroundStyle(.secondary)
                                    Spacer(minLength: 6)
                                    Text(name)
                                        .font(.caption.monospaced())
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 2)
                                        .background(Color.secondary.opacity(0.14), in: Capsule())
                                        .foregroundStyle(.primary)
                                        .fixedSize(horizontal: capsulesFit, vertical: true)
                                }
                            }
                        }
                        .padding(.vertical, 2)
                    } else {
                        LabeledContent("Secrets") {
                            Text(request.write ? "Read & Write" : "Read Only", comment: "What the grant may do with secrets.")
                        }
                        if !request.keys.isEmpty {
                            LabeledContent("Keys", value: request.keys.joined(separator: ", "))
                        }
                    }

                    if !request.sshHosts.isEmpty {
                        let matchedHosts = profile.openbao.ssh.hosts.filter { request.sshHosts.contains($0.name) }
                        VStack(alignment: .leading, spacing: 6) {
                            BaoAdaptiveStack(spacing: 6) {
                                Text("SSH Certificate")
                                    .font(.subheadline)
                                if !profile.openbao.ssh.role.isEmpty {
                                    Spacer(minLength: 6)
                                    Text("role: \(profile.openbao.ssh.role)", comment: "The OpenBao SSH signing role. %@ is the role's name (not translated).")
                                        .baoCaption2Font(monospaced: true)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            ForEach(matchedHosts) { host in
                                BaoAdaptiveStack(spacing: 8) {
                                    Text(verbatim: "\(host.user)@\(host.name)")
                                        .font(.subheadline)
                                        .foregroundStyle(.secondary)
                                    Spacer(minLength: 6)
                                    Text(host.principal)
                                        .font(.caption.monospaced())
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 2)
                                        .background(Color.secondary.opacity(0.14), in: Capsule())
                                        .foregroundStyle(.primary)
                                        .fixedSize(horizontal: capsulesFit, vertical: true)
                                }
                            }
                        }
                        .padding(.vertical, 2)
                    }

                    if request.push {
                        LabeledContent("Git Push") {
                            Text("1 hour", comment: "How long a git push token lasts.")
                        }
                    }

                    ForEach(request.selectedExtensions(profile: profile)) { ext in
                        VStack(alignment: .leading, spacing: 4) {
                            BaoAdaptiveStack(spacing: 8) {
                                Image(systemName: ext.icon)
                                    .font(.subheadline)
                                    .foregroundStyle(ext.elevated ? BaoTheme.elevated : BaoTheme.brand)
                                    .frame(width: iconColumnWidth, alignment: .center)
                                    .accessibilityHidden(true)
                                Text(ext.displayLabel)
                                    .font(.subheadline.weight(.medium))
                                if ext.elevated {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .baoCaption2Font()
                                        .foregroundStyle(BaoTheme.elevated)
                                        .accessibilityLabel("Elevated")
                                }
                                Spacer(minLength: 6)
                                Text(ext.deliverAs)
                                    .baoCaption2Font(monospaced: true)
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 2)
                                    .background(BaoTheme.brand.opacity(0.12), in: Capsule())
                                    .foregroundStyle(BaoTheme.brand)
                                    .fixedSize(horizontal: capsulesFit, vertical: true)
                            }
                            Text(ext.endpoint)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            if !ext.policy.isEmpty {
                                Text("Adds policy \(ext.policy)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Text(profile.hasRemoteTarget && request.target == .t3
                                 ? "Delivered to \(profile.targetDisplayName)"
                                 : "Shown in BaoBuddy")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 2)
                    }

                    if !request.why.isEmpty {
                        LabeledContent("Reason", value: request.why)
                    }
                }

                // Active workloads on remote target
                if profile.hasRemoteTarget && request.target == .t3 {
                    Section("Active Workloads on \(profile.targetDisplayName)") {
                        if model.isCheckingTasks {
                            HStack(spacing: 10) {
                                ProgressView()
                                Text("Checking running tasks…")
                                    .foregroundStyle(.secondary)
                            }
                        } else if let running = model.runningTasks {
                            if running.brokerUnavailable {
                                Label(
                                    "Couldn't check running tasks; this grant will reach any workloads active on \(profile.targetDisplayName).",
                                    systemImage: "exclamationmark.circle"
                                )
                                .font(.footnote)
                                .foregroundStyle(BaoTheme.elevated)
                            } else if running.tasks.isEmpty {
                                Label("No background tasks running.", systemImage: "checkmark.circle")
                                    .foregroundStyle(.secondary)
                            } else {
                                Label(
                                    "This grant will reach \(running.tasks.count) running tasks:",
                                    systemImage: "exclamationmark.triangle.fill"
                                )
                                .font(.footnote.weight(.medium))
                                .foregroundStyle(BaoTheme.elevated)
                                ForEach(running.tasks, id: \.self) { task in
                                    Text(task)
                                        .font(.footnote.monospaced())
                                }
                            }
                        }
                    }
                }

                Section("Audit Payload") {
                    LabeledContent("Policies") {
                        Text(request.openBaoPolicies(profile: profile).joined(separator: ", "))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Text(request.auditScope(profile: profile))
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("auditPayload")
                }

                if let error = model.errorMessage {
                    Section {
                        Label(error, systemImage: "xmark.octagon.fill")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .accessibilityIdentifier("approvalDetails")
            .listStyle(.insetGrouped)
            .navigationTitle("Approve Grant")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbarBackground(Color(.systemGroupedBackground), for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        model.dismissApproval()
                    }
                    .disabled(model.isApproving)
                }
            }
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 0) {
                    Divider()
                    Button {
                        BaoHaptics.impact(.medium)
                        Task { await model.approvePendingGrant() }
                    } label: {
                        HStack(spacing: 8) {
                            if model.isApproving {
                                ProgressView()
                            } else {
                                Image(systemName: model.biometry.systemImage)
                                    .accessibilityHidden(true)
                            }
                            Text(model.isApproving
                                 ? String(localized: "Authenticating…", comment: "Approve button title while Face ID or Touch ID is in progress.")
                                 : model.biometry.approveButtonTitle)
                                .font(.headline)
                        }
                        .frame(maxWidth: .infinity, minHeight: 46, alignment: .center)
                        .multilineTextAlignment(.center)
                    }
                    .primaryBaoButton(tint: accent)
                    .disabled(model.isApproving)
                    .accessibilityIdentifier("approveGrant")
                    .padding(.horizontal, 20)
                    .padding(.vertical, 12)
                }
                .background(.bar)
            }
        }
    }
}
