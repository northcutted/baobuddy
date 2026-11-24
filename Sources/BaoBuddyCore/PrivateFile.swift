import Foundation

/// Writes BaoBuddy's local state (profiles, grant accessors, activity) so other users on the
/// machine can't read it: the directory is 0700 and each file is created 0600 before any data
/// is written, then renamed into place. On iOS the file also gets Data Protection.
enum PrivateFile {
    /// `completeProtection` (iOS) makes the file unreadable while the device is locked; use it for
    /// files that are only touched while the app is in the foreground.
    static func write(_ data: Data, to url: URL, completeProtection: Bool = false) throws {
        let dir = url.deletingLastPathComponent()
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        #if os(macOS)
        // Tighten a directory an older version created with the default 0755.
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            guard rename(tmp.path, url.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        } catch {
            try? fm.removeItem(at: tmp)
            throw error
        }
        #else
        let protection: Data.WritingOptions = completeProtection
            ? .completeFileProtection
            : .completeFileProtectionUntilFirstUserAuthentication
        try data.write(to: url, options: [.atomic, protection])
        #endif
    }
}
