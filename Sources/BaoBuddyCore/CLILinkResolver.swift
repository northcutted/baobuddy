import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Detects whether a `bao-buddy` CLI symlink or binary on `PATH` or in standard bin directories
/// resolves to the running app's executable.
public enum CLILinkResolver {
    public struct DetectionResult: Equatable, Sendable {
        /// Full filesystem path of the discovered CLI symlink or binary.
        public let path: String
        /// User-friendly display path (with any matching home directory abbreviated to `~`).
        public let displayPath: String

        public init(path: String, displayPath: String) {
            self.path = path
            self.displayPath = displayPath
        }
    }

    /// Ordered, deduplicated search directories: `PATH` entries first, then `~/.local/bin`
    /// (for both the current `HOME` and the real passwd home directory), `/opt/homebrew/bin`,
    /// and `/usr/local/bin`.
    public static func standardSearchDirectories(
        environmentPATH: String? = ProcessInfo.processInfo.environment["PATH"],
        homeDirectories: [String]? = nil
    ) -> [String] {
        let homes = homeDirectories ?? currentUserHomeDirectories()
        var dirs: [String] = []
        var seen = Set<String>()

        func appendDir(_ raw: String) {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return }
            let expanded: String
            if trimmed == "~", let firstHome = homes.first {
                expanded = firstHome
            } else if trimmed.hasPrefix("~/"), let firstHome = homes.first {
                expanded = firstHome + String(trimmed.dropFirst(1))
            } else {
                expanded = trimmed
            }
            let normalized = URL(fileURLWithPath: expanded).standardizedFileURL.path
            if seen.insert(normalized).inserted {
                dirs.append(normalized)
            }
        }

        if let envPath = environmentPATH {
            for part in envPath.split(separator: ":", omittingEmptySubsequences: true) {
                appendDir(String(part))
            }
        }
        for home in homes {
            appendDir(home + "/.local/bin")
        }
        appendDir("/opt/homebrew/bin")
        appendDir("/usr/local/bin")
        return dirs
    }

    /// Returns both the environment/NS home directory and the real passwd home directory
    /// (deduplicated) so `~/.local/bin` is still detected even if `HOME` is overridden.
    public static func currentUserHomeDirectories() -> [String] {
        var homes: [String] = []
        var seen = Set<String>()
        func add(_ path: String?) {
            guard let path, !path.isEmpty else { return }
            let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
            if seen.insert(normalized).inserted {
                homes.append(normalized)
            }
        }
        add(NSHomeDirectory())
        #if canImport(Darwin)
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
            add(String(cString: dir))
        }
        #endif
        return homes
    }

    /// Finds an installed CLI command whose resolved symlink target matches `executablePath`.
    public static func detect(
        executablePath: String? = Bundle.main.executablePath,
        commandNames: [String] = ["bao-buddy"],
        searchDirectories: [String]? = nil,
        homeDirectories: [String]? = nil
    ) -> DetectionResult? {
        guard let executablePath, !executablePath.isEmpty else { return nil }
        let resolvedExecutable = URL(fileURLWithPath: executablePath)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
        let homes = homeDirectories ?? currentUserHomeDirectories()
        let dirs = searchDirectories ?? standardSearchDirectories(homeDirectories: homes)
        let fm = FileManager.default

        for dir in dirs {
            for name in commandNames {
                let candidate = URL(fileURLWithPath: dir).appendingPathComponent(name).path
                guard fm.fileExists(atPath: candidate), fm.isExecutableFile(atPath: candidate) else {
                    continue
                }
                let resolvedCandidate = URL(fileURLWithPath: candidate)
                    .resolvingSymlinksInPath()
                    .standardizedFileURL
                    .path
                if resolvedCandidate == resolvedExecutable {
                    return DetectionResult(
                        path: candidate,
                        displayPath: abbreviateHome(candidate, homes: homes)
                    )
                }
            }
        }
        return nil
    }

    /// Replaces any matching home directory prefix with `~/` for clean UI display.
    public static func abbreviateHome(_ path: String, homes: [String]) -> String {
        let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
        for home in homes.sorted(by: { $0.count > $1.count }) {
            let prefix = home.hasSuffix("/") ? home : home + "/"
            if normalized.hasPrefix(prefix) {
                return "~/" + String(normalized.dropFirst(prefix.count))
            }
        }
        return normalized
    }
}
