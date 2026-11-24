#if os(macOS)
import AppKit
import BaoBuddyCore
import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

/// Zero-dependency QR code renderer for macOS UI and Terminal CLI (`--qr`).
enum MacQRCode {
    /// Generates a sharp, nearest-neighbor `NSImage` with a clean quiet zone.
    static func makeImage(from string: String, dimension: CGFloat = 240) -> NSImage? {
        guard let ciImage = rawQRImage(from: string) else { return nil }
        let extent = ciImage.extent
        guard extent.width > 0, extent.height > 0 else { return nil }
        let scale = max(1, floor(dimension / extent.width))
        let transformed = ciImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let context = CIContext(options: nil)
        guard let cgImage = context.createCGImage(transformed, from: transformed.extent) else {
            return nil
        }
        return NSImage(cgImage: cgImage, size: NSSize(width: dimension, height: dimension))
    }

    /// Renders a compact Unicode half-block (`▀`/`▄`/`█`/` `) QR code for Terminal output.
    static func renderTerminalASCII(from string: String) -> String? {
        guard let ciImage = rawQRImage(from: string) else { return nil }
        let width = Int(ciImage.extent.width)
        let height = Int(ciImage.extent.height)
        guard width > 0, height > 0 else { return nil }

        let context = CIContext(options: nil)
        var pixels = [UInt8](repeating: 255, count: width * height)
        context.render(
            ciImage,
            toBitmap: &pixels,
            rowBytes: width,
            bounds: ciImage.extent,
            format: .L8,
            colorSpace: CGColorSpaceCreateDeviceGray()
        )

        func isDark(x: Int, y: Int) -> Bool {
            guard x >= 0, x < width, y >= 0, y < height else { return false }
            // CIImage origin is bottom-left; flip vertically for top-down printing.
            let flippedY = (height - 1) - y
            return pixels[flippedY * width + x] < 128
        }

        // Add 2-module quiet zone around the QR code for reliable scanning on dark terminals.
        let border = 2
        let totalW = width + border * 2
        let totalH = height + border * 2
        var lines: [String] = []

        var y = 0
        while y < totalH {
            var line = ""
            line.reserveCapacity(totalW)
            for x in 0..<totalW {
                let topDark = isDark(x: x - border, y: y - border)
                let botDark = (y + 1 < totalH) ? isDark(x: x - border, y: y + 1 - border) : false
                // Invert onto light background (white block = light module, space = dark module)
                // so dark terminal themes scan cleanly without inverting colors.
                switch (topDark, botDark) {
                case (false, false): line.append("█")
                case (false, true): line.append("▀")
                case (true, false): line.append("▄")
                case (true, true): line.append(" ")
                }
            }
            lines.append(line)
            y += 2
        }
        return lines.joined(separator: "\n")
    }

    private static func rawQRImage(from string: String) -> CIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        return filter.outputImage
    }
}

/// Native macOS pairing sheet displaying a scannable QR code for transferring a server profile to iPhone.
struct MacQRPairSheet: View {
    let profile: BaoProfile
    let disableClipboard: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var copiedTag: String?

    private var pairingURI: String? {
        try? ProfileTransferCodec.encodeURI(profile)
    }

    var body: some View {
        VStack(spacing: 16) {
            HStack(spacing: 12) {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(MacBaoTheme.brand.gradient)
                    .frame(width: 34, height: 34)
                    .overlay {
                        Image(systemName: "qrcode")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(MacBaoTheme.cream)
                    }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Pair iPhone — \(profile.displayName)")
                        .font(.headline)
                    Text(verbatim: profile.openbao.address)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            if let uri = pairingURI, let image = MacQRCode.makeImage(from: uri, dimension: 230) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 230, height: 230)
                    .padding(14)
                    .background(Color.white, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .shadow(color: .black.opacity(0.14), radius: 8, y: 2)

                VStack(spacing: 4) {
                    Text("Scan with BaoBuddy on your iPhone (or the iPhone Camera app).")
                        .font(.subheadline.weight(.medium))
                        .multilineTextAlignment(.center)
                    Text("Contains only non-secret server settings — never your Touch ID or SSH private keys.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            } else {
                Label("Could not generate QR code for this profile.", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }

            Divider()

            HStack {
                if !disableClipboard, let uri = pairingURI {
                    Button {
                        copyText(uri, tag: "uri")
                    } label: {
                        Label(
                            copiedTag == "uri" ? "Copied Link" : "Copy Pairing Link",
                            systemImage: copiedTag == "uri" ? "checkmark" : "link"
                        )
                    }
                    .buttonStyle(.bordered)
                }
                Spacer()
                Button("Done") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .tint(MacBaoTheme.brand)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 400)
    }

    private func copyText(_ text: String, tag: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        copiedTag = tag
        Task {
            try? await Task.sleep(for: .seconds(2))
            if copiedTag == tag { copiedTag = nil }
        }
    }
}
#endif
