@preconcurrency import AVFoundation
import BaoBuddyCore
import SwiftUI

/// Native iOS camera QR code scanner for pairing a BaoBuddy server from Mac Settings or Terminal (`--qr`).
struct QRScannerSheetView: View {
    @Environment(\.dismiss) private var dismiss
    let enforceTLSPinning: Bool
    let onScanned: (BaoProfile) -> Void

    @State private var scanError: String?
    @State private var cameraDenied: Bool = false

    var body: some View {
        NavigationStack {
            ZStack {
                if cameraDenied {
                    ContentUnavailableView(
                        "Camera Access Required",
                        systemImage: "camera.fill",
                        description: Text("Allow camera access for BaoBuddy in iOS Settings to scan pairing QR codes.")
                    )
                } else {
                    QRCameraPreview(
                        onCode: { payload in
                            handleScannedCode(payload)
                        },
                        onPermissionDenied: {
                            cameraDenied = true
                        }
                    )
                    .ignoresSafeArea()

                    VStack {
                        Spacer()
                        RoundedRectangle(cornerRadius: 20, style: .continuous)
                            .strokeBorder(BaoTheme.brand, lineWidth: 3)
                            .frame(width: 240, height: 240)
                        Spacer()
                        VStack(spacing: 6) {
                            if let scanError {
                                Label(scanError, systemImage: "exclamationmark.triangle.fill")
                                    .font(.caption.weight(.medium))
                                    .foregroundStyle(.red)
                                    .multilineTextAlignment(.center)
                            }
                            Text("Point at the QR code shown in BaoBuddy on your Mac or `bao-buddy export-profile --qr`.")
                                .font(.footnote)
                                .foregroundStyle(.white)
                                .multilineTextAlignment(.center)
                        }
                        .padding(14)
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .padding(.horizontal, 20)
                        .padding(.bottom, 24)
                    }
                }
            }
            .navigationTitle("Scan Pairing QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func handleScannedCode(_ raw: String) {
        do {
            let profile = try ProfileTransferCodec.decode(
                text: raw,
                requireHostKey: true,
                requireTLSPinning: enforceTLSPinning
            )
            BaoHaptics.notify(.success)
            dismiss()
            onScanned(profile)
        } catch {
            scanError = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }
}

/// Confirmation sheet shown whenever a profile arrives via QR code or `baobuddy://import?p=...`
/// so a scanned/tapped link can never silently add or overwrite a server without explicit review.
struct ConfirmProfileImportSheet: View {
    let profile: BaoProfile
    let plan: ProfileImportPlan?
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 12) {
                        BaoBuddyEmblem(tint: BaoTheme.brand, size: 42)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(profile.displayName)
                                .font(.headline)
                            Text(verbatim: profile.openbao.address)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Section("Server Details") {
                    if !profile.openbao.namespace.isEmpty {
                        LabeledContent("Namespace", value: profile.openbao.namespace)
                    }
                    LabeledContent("Username (sub)", value: profile.openbao.jwtAuth.subject)
                    LabeledContent("TLS Pinning") {
                        Text(profile.openbao.isTLSPinned ? "Pinned Certificate" : "System CAs")
                    }
                    LabeledContent("Max Grant") {
                        Text("\(profile.openbao.maxHours) hours", comment: "The grant's duration. %lld is a number of hours.")
                    }
                    if !profile.configuredRemoteTargets.isEmpty {
                        LabeledContent(
                            "Remote Targets",
                            value: profile.configuredRemoteTargets.map(\.displayName).joined(separator: ", ")
                        )
                    }
                }

                if let replaced = plan?.replaces {
                    Section {
                        Label(
                            "Replaces your existing server \(replaced.displayName).",
                            systemImage: "arrow.triangle.2.circlepath"
                        )
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(BaoTheme.elevated)
                        ForEach(plan?.changes ?? [], id: \.self) { change in
                            Text("Changes: \(change)", comment: "A setting that an imported server profile changes. %@ names the setting.")
                                .font(.footnote)
                        }
                    }
                }

                let notices = plan?.notices ?? []
                if !notices.isEmpty {
                    Section("Review") {
                        ForEach(notices, id: \.self) { notice in
                            Label(notice, systemImage: "exclamationmark.triangle")
                                .font(.footnote)
                                .foregroundStyle(BaoTheme.elevated)
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Import Server?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import", action: onConfirm)
                        .fontWeight(.semibold)
                }
            }
        }
    }
}

private struct QRCameraPreview: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    let onPermissionDenied: () -> Void

    func makeUIViewController(context: Context) -> QRCameraViewController {
        let controller = QRCameraViewController()
        controller.onCode = onCode
        controller.onPermissionDenied = onPermissionDenied
        return controller
    }

    func updateUIViewController(_ uiViewController: QRCameraViewController, context: Context) {}
}

private final class QRCameraViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    var onPermissionDenied: (() -> Void)?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    /// The last code handed to `onCode`. A code that fails to import is ignored while it stays in
    /// view, but scanning continues so a different code can be tried.
    private var lastValue: String?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        checkPermissionsAndConfigure()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            let captureSession = session
            DispatchQueue.global(qos: .userInitiated).async {
                captureSession.stopRunning()
            }
        }
    }

    private func checkPermissionsAndConfigure() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted {
                        self?.configureSession()
                    } else {
                        self?.onPermissionDenied?()
                    }
                }
            }
        default:
            onPermissionDenied?()
        }
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            onPermissionDenied?()
            return
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        self.previewLayer = preview

        let captureSession = session
        DispatchQueue.global(qos: .userInitiated).async {
            captureSession.startRunning()
        }
    }

    nonisolated func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let first = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = first.stringValue,
              !value.isEmpty else {
            return
        }
        Task { @MainActor [weak self] in
            guard let self, self.lastValue != value else { return }
            self.lastValue = value
            self.onCode?(value)
        }
    }
}
