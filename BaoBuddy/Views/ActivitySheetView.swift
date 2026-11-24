import BaoBuddyCore
import SwiftUI

/// Displays the non-secret local grant activity log on iOS. In Demo Mode it shows the in-memory
/// demo log instead, so demo grants never mix with (or reach) the real one.
struct ActivitySheetView: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var entries: [GrantActivityEntry] = []
    @State private var confirmClear: Bool = false
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    var body: some View {
        NavigationStack {
            List {
                if entries.isEmpty {
                    ContentUnavailableView(
                        "No Activity Yet",
                        systemImage: "clock.arrow.circlepath",
                        description: Text("Grants approved or revoked on this iPhone appear here. Metadata only — never tokens or keys.")
                    )
                } else {
                    ForEach(entries) { entry in
                        VStack(alignment: .leading, spacing: 4) {
                            BaoAdaptiveStack(spacing: 6) {
                                HStack(spacing: 6) {
                                    Image(systemName: entry.action.systemImage)
                                        .foregroundStyle(
                                            entry.action == .revoked
                                                ? Color.secondary
                                                : (entry.elevated ? BaoTheme.elevated : BaoTheme.active)
                                        )
                                        .accessibilityHidden(true)
                                    Text(entry.action.displayTitle)
                                        .font(.subheadline.weight(.semibold))
                                    // Orange alone marks an elevated grant; with Differentiate
                                    // Without Color it is also named.
                                    if entry.elevated && differentiateWithoutColor {
                                        BaoStatusPill(title: "Elevated", tint: BaoTheme.elevated, symbol: "exclamationmark.triangle.fill")
                                    }
                                }
                                Spacer()
                                Text(entry.timestamp, style: .relative)
                                    .baoCaption2Font()
                                    .foregroundStyle(.secondary)
                            }
                            Text(verbatim: "\(entry.serverName) → \(entry.targetName)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if !entry.policies.isEmpty {
                                let policyList = entry.policies.joined(separator: ", ")
                                Text(entry.hours > 0
                                     ? String(localized: "\(policyList) (\(entry.hours)h)", comment: "Activity log line. %1$@ is a comma-separated list of OpenBao policy names (not translated); %2$lld is the grant's length in hours, abbreviated h.")
                                     : policyList)
                                    .baoCaption2Font(monospaced: true)
                                    .foregroundStyle(.secondary)
                            }
                            if !entry.why.isEmpty {
                                Text(entry.why)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 2)
                        .accessibilityElement(children: .combine)
                        .accessibilityValue(entry.elevated && !differentiateWithoutColor ? Text("Elevated") : Text(verbatim: ""))
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Recent Activity")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier("activityDone")
                }
                if !entries.isEmpty {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Clear", role: .destructive) {
                            confirmClear = true
                        }
                    }
                }
            }
            .onAppear {
                entries = model.isDemoMode ? model.demoActivity : GrantActivityStore().load()
            }
            .confirmationDialog(
                "Clear Local Activity History?",
                isPresented: $confirmClear,
                titleVisibility: .visible
            ) {
                Button("Clear History", role: .destructive) {
                    if model.isDemoMode {
                        model.demoActivity = []
                    } else {
                        try? GrantActivityStore().clear()
                    }
                    entries = []
                }
                Button("Cancel", role: .cancel) {}
            }
        }
    }
}
