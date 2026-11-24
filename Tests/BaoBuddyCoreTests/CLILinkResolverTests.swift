@testable import BaoBuddyCore
import Foundation
import XCTest

final class CLILinkResolverTests: XCTestCase {
    private func makeTempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("baobuddy-cli-resolver-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
        }
        return url
    }

    private func makeExecutable(at url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "#!/bin/sh\nexit 0\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    }

    func testDetectsSymlinkInLocalBinMatchingAppBinary() throws {
        let root = try makeTempDir()
        let appBinary = root.appendingPathComponent("Applications/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper")
        try makeExecutable(at: appBinary)

        let fakeHome = root.appendingPathComponent("Users/alice")
        let localBin = fakeHome.appendingPathComponent(".local/bin")
        try FileManager.default.createDirectory(at: localBin, withIntermediateDirectories: true)
        let symlink = localBin.appendingPathComponent("bao-buddy")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: appBinary)

        let dirs = CLILinkResolver.standardSearchDirectories(
            environmentPATH: "/usr/bin:/bin",
            homeDirectories: [fakeHome.path]
        )
        let result = CLILinkResolver.detect(
            executablePath: appBinary.path,
            searchDirectories: dirs,
            homeDirectories: [fakeHome.path]
        )
        XCTAssertEqual(result?.path, symlink.standardizedFileURL.path)
        XCTAssertEqual(result?.displayPath, "~/.local/bin/bao-buddy")
    }

    func testDetectsSymlinkOnPATHAndIgnoresOtherBinariesOrBrokenLinks() throws {
        let root = try makeTempDir()
        let appBinary = root.appendingPathComponent("Applications/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper")
        let otherBinary = root.appendingPathComponent("Other/bao-buddy")
        try makeExecutable(at: appBinary)
        try makeExecutable(at: otherBinary)

        let dir1 = root.appendingPathComponent("bin-wrong")
        let dir2 = root.appendingPathComponent("bin-broken")
        let dir3 = root.appendingPathComponent("opt/homebrew/bin")
        for dir in [dir1, dir2, dir3] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        try FileManager.default.createSymbolicLink(
            at: dir1.appendingPathComponent("bao-buddy"),
            withDestinationURL: otherBinary
        )
        try FileManager.default.createSymbolicLink(
            at: dir2.appendingPathComponent("bao-buddy"),
            withDestinationURL: root.appendingPathComponent("does-not-exist")
        )
        let goodLink = dir3.appendingPathComponent("bao-buddy")
        try FileManager.default.createSymbolicLink(at: goodLink, withDestinationURL: appBinary)

        let dirs = CLILinkResolver.standardSearchDirectories(
            environmentPATH: [dir1.path, dir2.path, dir3.path].joined(separator: ":"),
            homeDirectories: [root.appendingPathComponent("empty-home").path]
        )
        let result = CLILinkResolver.detect(
            executablePath: appBinary.path,
            searchDirectories: dirs,
            homeDirectories: [root.appendingPathComponent("empty-home").path]
        )
        XCTAssertEqual(result?.path, goodLink.standardizedFileURL.path)
        XCTAssertEqual(result?.displayPath, goodLink.standardizedFileURL.path)
    }

    func testStandardSearchDirectoriesIncludeHomebrewAndUsrLocalBin() {
        let dirs = CLILinkResolver.standardSearchDirectories(
            environmentPATH: "/usr/bin:/bin",
            homeDirectories: ["/Users/demo"]
        )
        XCTAssertTrue(dirs.contains("/Users/demo/.local/bin"))
        XCTAssertTrue(dirs.contains("/opt/homebrew/bin"))
        XCTAssertTrue(dirs.contains("/usr/local/bin"))
    }
}
