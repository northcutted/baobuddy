// Quit only the registered GUI at the bundle being replaced. CLI and MCP sessions
// use the same executable and may be serving an active grant.
import AppKit

func install(source: URL, destination: URL) throws {
    let manager = FileManager.default
    let stagingDirectory = try manager.url(for: .itemReplacementDirectory, in: .userDomainMask,
                                           appropriateFor: destination, create: true)
    defer { try? manager.removeItem(at: stagingDirectory) }
    let staged = stagingDirectory.appendingPathComponent(destination.lastPathComponent)
    try manager.copyItem(at: source, to: staged)

    let running = NSRunningApplication.runningApplications(withBundleIdentifier: "com.northcutt.BaoBuddy.Helper")
    for app in running where app.bundleURL?.resolvingSymlinksInPath().standardizedFileURL.path == destination.path && app.activationPolicy != .prohibited {
        guard app.terminate() else { throw CocoaError(.userCancelled) }
        let deadline = Date().addingTimeInterval(5)
        while !app.isTerminated && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        guard app.isTerminated else { throw CocoaError(.userCancelled) }
    }

    // The old bundle stays at the install path until the complete replacement is ready.
    // An already-running CLI can keep executing its original mapped binary.
    let flags = manager.fileExists(atPath: destination.path) ? RENAME_SWAP : RENAME_EXCL
    guard renamex_np(staged.path, destination.path, UInt32(flags)) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

guard CommandLine.arguments.count == 3 else {
    fputs("Usage: install-mac-helper.swift SOURCE_APP DESTINATION_APP\n", stderr)
    exit(2)
}
do {
    try install(source: URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL,
                destination: URL(fileURLWithPath: CommandLine.arguments[2]).standardizedFileURL)
} catch {
    fputs("Could not install the helper: \(error.localizedDescription)\n", stderr)
    exit(1)
}
