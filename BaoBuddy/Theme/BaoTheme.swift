import LocalAuthentication
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Context-aware biometric descriptor following Apple's LocalAuthentication HIG.
struct BiometryDescriptor: Equatable, Sendable {
    let name: String
    let systemImage: String

    var approveButtonTitle: String {
        name.isEmpty
            ? String(localized: "Approve Grant", comment: "Button that approves a grant when the device has no Face ID or Touch ID.")
            : String(localized: "Approve with \(name)", comment: "Button that approves a grant. %@ is Face ID, Touch ID or Optic ID (Apple product names, not translated).")
    }

    /// The biometric method's name for use inside sentences: "Face ID", "Touch ID", or a generic word.
    var nameInSentence: String {
        name.isEmpty
            ? String(localized: "biometrics", comment: "Used inside sentences in place of Face ID or Touch ID, for example: …signs a JWT with biometrics. Lowercase in English.")
            : name
    }

    static var current: BiometryDescriptor {
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        switch context.biometryType {
        case .faceID:
            return BiometryDescriptor(name: "Face ID", systemImage: "faceid")
        case .touchID:
            return BiometryDescriptor(name: "Touch ID", systemImage: "touchid")
        case .opticID:
            return BiometryDescriptor(name: "Optic ID", systemImage: "opticid")
        default:
            return BiometryDescriptor(name: "", systemImage: "lock.shield")
        }
    }
}

/// BaoBuddy brand tokens layered over native iOS system materials and Liquid Glass chrome.
/// The palette is defined once in `Branding/generate.py` and documented in `Branding/README.md`.
enum BaoTheme {
    /// Bao Teal (#0F766E light, #14B8A6 dark). Primary brand colour and app accent.
    static let brand = Color("AccentColor")

    /// Elevated scope accent (system orange).
    static let elevated = Color.orange

    /// Active grant indicator.
    static let active = Color.green

    /// Steam Cream (#FFF6E5): the bun on brand surfaces.
    static let cream = Color(red: 1.0, green: 0.965, blue: 0.898)

    /// Soy Ink (#1E293B): the face and lettering on cream.
    static let ink = Color(red: 0.118, green: 0.161, blue: 0.231)
}

/// The app icon in miniature: a continuous-corner tile in `tint` with the cream bao mark.
/// Pass `BaoTheme.elevated` for elevated scopes so the whole tile changes colour,
/// rather than adding a ring around an unchanged image.
struct BaoBuddyEmblem: View {
    var tint: Color = BaoTheme.brand
    var size: CGFloat = 48

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.225, style: .continuous)
            .fill(tint.gradient)
            .frame(width: size, height: size)
            .overlay {
                Image("BaoBuddyMark")
                    .resizable()
                    .scaledToFit()
                    .foregroundStyle(BaoTheme.cream)
                    .padding(size * 0.12)
            }
            .accessibilityHidden(true)
    }
}

/// Cohesive macOS/iOS gradient rounded-square icon tile used on server and hardware key cards.
struct BaoIconBadge: View {
    let symbol: String
    var tint: Color = BaoTheme.brand
    var size: CGFloat = 36

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
            .fill(tint.gradient)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: symbol)
                    .font(.system(size: size * 0.46, weight: .semibold))
                    .foregroundStyle(BaoTheme.cream)
            }
            .accessibilityHidden(true)
    }
}

/// Cohesive capsule status pill matching the macOS Settings & Menu Bar visual grammar.
/// The title always states the status, so it never rests on the tint alone.
struct BaoStatusPill: View {
    let title: LocalizedStringKey
    var tint: Color = BaoTheme.brand
    var symbol: String?

    var body: some View {
        HStack(spacing: 4) {
            if let symbol {
                Image(systemName: symbol)
                    .baoCaption2Font()
                    .accessibilityHidden(true)
            }
            Text(title)
                .baoCaption2Font(.semibold)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(tint.opacity(0.14), in: Capsule())
        .foregroundStyle(tint)
        .fixedSize()
    }
}

/// Inline Demo Mode card placed as the top List section so it sits cleanly below
/// navigation bars and large titles on every iPhone and iPad layout.
struct BaoDemoBanner: View {
    let onExit: () -> Void

    var body: some View {
        BaoAdaptiveStack(spacing: 10) {
            BaoIconBadge(symbol: "flask.fill", tint: BaoTheme.brand, size: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text("Demo Mode")
                    .font(.subheadline.weight(.semibold))
                Text("Simulated server — nothing leaves this device.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Exit") {
                BaoHaptics.impact()
                onExit()
            }
            .font(.caption.weight(.semibold))
            .buttonStyle(.bordered)
            .controlSize(.small)
            .tint(BaoTheme.brand)
            .fixedSize()
            .accessibilityLabel("Exit Demo Mode")
            .accessibilityInputLabels([Text("Exit"), Text("Exit Demo Mode")])
        }
        .padding(.vertical, 2)
    }
}

/// Keeps a `List` or `ScrollView` full-width on wide iPad screens so swiping in the side
/// margins still scrolls and the scroll indicator sits at the screen edge, while centering
/// the scroll content in a 740pt readable column via horizontal content margins.
struct BaoReadableWidthModifier: ViewModifier {
    private static let maxColumnWidth: CGFloat = 740
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @State private var containerWidth: CGFloat = 0

    private var horizontalMargin: CGFloat? {
        guard horizontalSizeClass == .regular, containerWidth > Self.maxColumnWidth else {
            return nil
        }
        return max(16, (containerWidth - Self.maxColumnWidth) / 2)
    }

    func body(content: Content) -> some View {
        content
            .onGeometryChange(for: CGFloat.self) { proxy in
                proxy.size.width
            } action: { newWidth in
                if abs(containerWidth - newWidth) > 0.5 {
                    containerWidth = newWidth
                }
            }
            .contentMargins(.horizontal, horizontalMargin, for: .scrollContent)
    }
}

/// Renders a column-aligned large title as the top section of an inset-grouped `List` on
/// regular-width iPad screens, keeping the title aligned with the 740pt column while
/// `NavigationStack` stays full-width native.
struct BaoRegularColumnTitle: View {
    let title: LocalizedStringKey
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    var body: some View {
        if horizontalSizeClass == .regular {
            Section {
                Text(title)
                    .font(.largeTitle.bold())
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityAddTraits(.isHeader)
                    .listRowInsets(EdgeInsets(top: 0, leading: 0, bottom: 0, trailing: 0))
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
        }
    }
}

extension View {
    func baoReadableWidth() -> some View {
        modifier(BaoReadableWidthModifier())
    }
}

/// Applies iOS 26+ Liquid Glass prominent capsule button styling when available,
/// falling back cleanly to native capsule `.borderedProminent` on iOS 18.
struct PrimaryCapsuleButtonModifier: ViewModifier {
    let tint: Color

    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            content
                .buttonStyle(.glassProminent)
                .tint(tint)
        } else {
            content
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.capsule)
                .tint(tint)
        }
    }
}

extension View {
    func primaryBaoButton(tint: Color = BaoTheme.brand) -> some View {
        modifier(PrimaryCapsuleButtonModifier(tint: tint))
    }
}

/// A row that becomes a leading-aligned column at accessibility text sizes, where
/// side-by-side content would squeeze its text into a column a word or two wide.
struct BaoAdaptiveStack<Content: View>: View {
    var alignment: VerticalAlignment = .center
    var spacing: CGFloat?
    @ViewBuilder let content: Content
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        let layout = dynamicTypeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
            : AnyLayout(HStackLayout(alignment: alignment, spacing: spacing))
        layout {
            content
        }
    }
}

/// Caption 2 at the default sizes; at accessibility sizes, where Caption 2 grows
/// least of all the text styles, Caption 1.
struct BaoCaption2FontModifier: ViewModifier {
    var weight: Font.Weight?
    var monospaced = false
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    func body(content: Content) -> some View {
        var font: Font = dynamicTypeSize.isAccessibilitySize ? .caption : .caption2
        if let weight {
            font = font.weight(weight)
        }
        if monospaced {
            font = font.monospaced()
        }
        return content.font(font)
    }
}

extension View {
    func baoCaption2Font(_ weight: Font.Weight? = nil, monospaced: Bool = false) -> some View {
        modifier(BaoCaption2FontModifier(weight: weight, monospaced: monospaced))
    }
}

/// Segmented controls keep their text size; at accessibility text sizes a menu
/// picker, whose label and value grow with the text, takes their place.
struct BaoSegmentedPickerModifier: ViewModifier {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    func body(content: Content) -> some View {
        if dynamicTypeSize.isAccessibilitySize {
            content.pickerStyle(.menu)
        } else {
            content.pickerStyle(.segmented)
        }
    }
}

extension View {
    func baoSegmentedPicker() -> some View {
        modifier(BaoSegmentedPickerModifier())
    }
}

/// A form text field whose placeholder names it, or shows `prompt` (an example
/// value) while VoiceOver reads the name.  At accessibility text sizes, where a
/// long placeholder would be shrunk to fit one line, the name is shown above the
/// field instead, where it can wrap.
struct BaoTextField: View {
    let title: LocalizedStringKey
    var prompt: String?
    let accessibilityAxis: Axis
    @Binding var text: String
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    init(_ title: LocalizedStringKey, text: Binding<String>, prompt: String? = nil, accessibilityAxis: Axis = .horizontal) {
        self.title = title
        self.prompt = prompt
        self.accessibilityAxis = accessibilityAxis
        self._text = text
    }

    var body: some View {
        if dynamicTypeSize.isAccessibilitySize {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                TextField(text: $text, prompt: Text(verbatim: ""), axis: accessibilityAxis) {
                    Text(title)
                }
                .accessibilityLabel(Text(title))
            }
        } else if let prompt {
            TextField(title, text: $text, prompt: Text(verbatim: prompt))
        } else {
            TextField(title, text: $text)
        }
    }
}

@MainActor
enum BaoHaptics {
    static func impact(_ style: UIImpactFeedbackGenerator.FeedbackStyle = .light) {
        #if canImport(UIKit)
        UIImpactFeedbackGenerator(style: style).impactOccurred()
        #endif
    }

    static func notify(_ type: UINotificationFeedbackGenerator.FeedbackType) {
        #if canImport(UIKit)
        UINotificationFeedbackGenerator().notificationOccurred(type)
        #endif
    }
}
