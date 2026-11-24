@testable import BaoBuddyCore
import XCTest

final class RemoteStatusSummaryTests: XCTestCase {
    func testParsesExactReceiverActiveStatusWithReasonAndPresentSSH() {
        let raw = """
        Secrets: active (59m left; db-readonly) — CHG-1042 deploy (staging)
        SSH: certificate present
        Push: active (58m left)
        """
        let summary = RemoteStatusSummary.parse(raw)
        XCTAssertEqual(summary.headerState, .active)
        XCTAssertTrue(summary.hasActiveGrant)
        XCTAssertFalse(summary.hasUnknownStatus)
        XCTAssertEqual(summary.entries.count, 3)

        XCTAssertEqual(summary.entries[0].id, "secrets")
        XCTAssertEqual(summary.entries[0].state, .active)
        XCTAssertEqual(summary.entries[0].statusText, "Active · 59m left")
        XCTAssertEqual(summary.entries[0].detail, "db-readonly — CHG-1042 deploy (staging)")

        XCTAssertEqual(summary.entries[1].id, "ssh")
        XCTAssertEqual(summary.entries[1].state, .active)
        XCTAssertEqual(summary.entries[1].statusText, "Active")
        XCTAssertEqual(summary.entries[1].detail, "")

        XCTAssertEqual(summary.entries[2].id, "push")
        XCTAssertEqual(summary.entries[2].state, .active)
        XCTAssertEqual(summary.entries[2].statusText, "Active · 58m left")
        XCTAssertEqual(summary.entries[2].detail, "")
    }

    func testUnknownSecretsOverridesHeaderToWarningEvenWhenSSHCertPresent() {
        let raw = """
        Secrets: unknown (couldn't check with OpenBao: Get "https://x": dial tcp 127.0.0.1:8200: connect: connection refused)
        SSH: certificate present
        Push: no token
        """
        let summary = RemoteStatusSummary.parse(raw)
        XCTAssertEqual(summary.headerState, .unknown)
        XCTAssertTrue(summary.hasUnknownStatus)
        XCTAssertTrue(summary.hasActiveGrant)

        XCTAssertEqual(summary.entries[0].state, .unknown)
        XCTAssertEqual(summary.entries[0].statusText, "Unknown")
        XCTAssertEqual(
            summary.entries[0].detail,
            #"couldn't check with OpenBao: Get "https://x": dial tcp 127.0.0.1:8200: connect: connection refused"#
        )

        XCTAssertEqual(summary.entries[1].state, .active)
        XCTAssertEqual(summary.entries[1].statusText, "Active")
        XCTAssertEqual(summary.entries[1].detail, "")

        XCTAssertEqual(summary.entries[2].state, .inactive)
        XCTAssertEqual(summary.entries[2].statusText, "None")
    }

    func testActiveSSHPreservesCaseSensitiveUsernameVerbatimOnDetailLine() {
        let raw = """
        Secrets: active (1h 59m left; demo • files: db-creds.json).
        SSH: ops@staging-web (1h 59m left).
        Push: no token.
        """
        let summary = RemoteStatusSummary.parse(raw)
        XCTAssertEqual(summary.headerState, .active)
        XCTAssertEqual(summary.entries[0].statusText, "Active · 1h 59m left")
        XCTAssertEqual(summary.entries[0].detail, "demo • files: db-creds.json")

        XCTAssertEqual(summary.entries[1].statusText, "Active · 1h 59m left")
        XCTAssertEqual(summary.entries[1].detail, "ops@staging-web")
    }

    func testIdleAndLegacyFormats() {
        let idle = RemoteStatusSummary.parse("""
        Secrets: no grant
        SSH: no certificate
        Push: no token
        """)
        XCTAssertEqual(idle.headerState, .inactive)
        XCTAssertFalse(idle.hasActiveGrant)
        XCTAssertEqual(idle.entries.map(\.statusText), ["None", "None", "None"])

        let legacy = RemoteStatusSummary.parse("""
        Secrets: read until 08:42 AM, why: deploy.
        SSH: docker until 08:42 AM.
        Push: no token.
        """)
        XCTAssertEqual(legacy.headerState, .active)
        XCTAssertEqual(legacy.entries[0].statusText, "Active")
        XCTAssertEqual(legacy.entries[0].detail, "read until 08:42 AM, why: deploy")
        XCTAssertEqual(legacy.entries[1].statusText, "Active")
        XCTAssertEqual(legacy.entries[1].detail, "docker until 08:42 AM")
    }

    func testDemoTimeLeftIsFormattedInTheUsersLanguageWithoutChangingOtherRows() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let parsed = RemoteStatusSummary.parse("""
        Secrets: active (1h 59m left; demo).
        SSH: certificate present.
        Push: no token.
        """)
        let english = parsed.localizingTimeLeft(until: now.addingTimeInterval(7_170), now: now, locale: Locale(identifier: "en_US"))
        XCTAssertEqual(english.entries[0].statusText, "Active · 1h 59m left")
        XCTAssertEqual(english.entries[0].detail, "demo")
        // Rows without a time left, active or not, keep the host's text.
        XCTAssertEqual(english.entries[1].statusText, "Active")
        XCTAssertEqual(english.entries[2].statusText, "None")
        XCTAssertEqual(english.rawText, parsed.rawText)

        let german = parsed.localizingTimeLeft(until: now.addingTimeInterval(7_170), now: now, locale: Locale(identifier: "de_DE"))
        XCTAssertNotEqual(german.entries[0].statusText, english.entries[0].statusText)
        XCTAssertTrue(german.entries[0].statusText.contains("59"))

        XCTAssertEqual(RemoteStatusSummary.localizedTimeLeft(seconds: 20, locale: Locale(identifier: "en_US")), "1m left")
        XCTAssertEqual(RemoteStatusSummary.localizedTimeLeft(seconds: 7_200, locale: Locale(identifier: "en_US")), "2h left")
    }

    func testUnrecognizedOutputBecomesUnavailable() {
        let summary = RemoteStatusSummary.parse("Connection refused")
        XCTAssertTrue(summary.entries.isEmpty)
        XCTAssertEqual(summary.unavailableReason, "Connection refused")
    }
}
