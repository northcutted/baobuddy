import ActivityKit
import BaoBuddyCore
import SwiftUI
import WidgetKit

@main
struct BaoBuddyLiveActivityBundle: WidgetBundle {
    var body: some Widget {
        GrantLiveActivityWidget()
    }
}

struct GrantLiveActivityWidget: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: GrantActivityAttributes.self) { context in
            let tint: Color = context.state.isElevated ? .orange : Color.baoTealBright
            HStack(spacing: 12) {
                Image("BaoBuddyGlyphUnlocked")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 34, height: 28)
                    .foregroundStyle(tint)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: "\(context.attributes.serverName) • \(context.attributes.targetName)")
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                    Text(context.state.scopeSummary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    if !context.attributes.reason.isEmpty {
                        Text(context.attributes.reason)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                // Server, scope, and reason are redacted on a locked device; only the countdown shows.
                .privacySensitive()

                Spacer(minLength: 8)

                VStack(alignment: .trailing, spacing: 2) {
                    HStack(spacing: 4) {
                        // Elevated grants are marked by shape as well as orange; VoiceOver
                        // reads the symbol's system name ("Warning").
                        if context.state.isElevated {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.subheadline)
                        }
                        Text(timerInterval: context.state.countdown, countsDown: true)
                            .font(.headline.monospacedDigit())
                            .multilineTextAlignment(.trailing)
                    }
                    .foregroundStyle(tint)
                    Text("remaining", comment: "Live Activity: shown under the countdown of time left on a grant, as in 1:59:00 remaining.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        } dynamicIsland: { context in
            let tint: Color = context.state.isElevated ? .orange : Color.baoTealBright
            return DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label {
                        Text(context.attributes.targetName)
                    } icon: {
                        Image("BaoBuddyGlyphUnlocked")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 18, height: 15)
                            .accessibilityHidden(true)
                    }
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(tint)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    HStack(spacing: 3) {
                        if context.state.isElevated {
                            Image(systemName: "exclamationmark.triangle.fill")
                        }
                        Text(timerInterval: context.state.countdown, countsDown: true)
                            .monospacedDigit()
                    }
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(tint)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: "\(context.attributes.serverName) — \(context.state.scopeSummary)")
                            .font(.caption)
                            .lineLimit(1)
                        if !context.attributes.reason.isEmpty {
                            Text(context.attributes.reason)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .privacySensitive()
                }
            } compactLeading: {
                HStack(spacing: 2) {
                    BrandGlyph()
                    if context.state.isElevated {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption2)
                    }
                }
                .foregroundStyle(tint)
            } compactTrailing: {
                Text(timerInterval: context.state.countdown, countsDown: true)
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(tint)
                    .frame(maxWidth: 48)
            } minimal: {
                BrandGlyph()
                    .foregroundStyle(tint)
            }
        }
    }
}

/// Unlocked bao glyph sized for the Dynamic Island compact and minimal slots.
private struct BrandGlyph: View {
    var body: some View {
        Image("BaoBuddyGlyphUnlocked")
            .resizable()
            .scaledToFit()
            .frame(width: 22, height: 18)
            .accessibilityLabel(Text("BaoBuddy grant active", comment: "VoiceOver label for the BaoBuddy icon in the Dynamic Island while a grant is active. BaoBuddy is the app's name."))
    }
}

private extension GrantActivityAttributes.ContentState {
    /// Now until expiry.  Once the grant has expired the range is empty rather
    /// than inverted: an inverted range traps, crashing the widget extension.
    var countdown: ClosedRange<Date> {
        let now = Date.now
        return min(now, expiresAt)...expiresAt
    }
}

private extension Color {
    /// Bao Teal Bright (#14B8A6), matching the dark-mode AccentColor.
    static let baoTealBright = Color(red: 0.078, green: 0.722, blue: 0.651)
}
