import UIKit
import XCTest

/// App Store screenshots, captured by `make screenshots` (fastlane snapshot, see fastlane/Snapfile)
/// for every store locale and device in `.github/ios-release.json`.
///
/// The test drives the real UI in Demo Mode, which signs with an in-memory key on the Simulator,
/// so no Face ID prompt appears. Controls are found by accessibility identifier, never by their
/// (localized) labels, so the same walk works in every language. Outside fastlane the
/// `snapshot` calls do nothing and the test runs as an ordinary UI test of the demo flow.
@MainActor
final class ScreenshotTests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testAllScreenshots() throws {
        let app = XCUIApplication()
        setupSnapshot(app)
        // The composer starts with the demo's sample reason, in the capture's language: XCTest
        // can't reliably type text the Simulator's keyboard has no keys for.
        app.launchArguments += ["-BaoBuddyDemo", "-BaoBuddyDemoSampleReason"]
        XCUIDevice.shared.orientation = .portrait
        XCUIDevice.shared.appearance = .light
        app.launch()

        // The Activity button appears only once a server (here the demo one) is set up.
        let activity = app.buttons["activityButton"]
        if !activity.waitForExistence(timeout: 15) {
            // The first launch after installing can come up without its launch arguments.
            app.terminate()
            app.launch()
        }
        XCTAssertTrue(activity.waitForExistence(timeout: 15), "Grants opens in Demo Mode.")
        let review = app.buttons["reviewAndApprove"]

        // 02: a standard grant (read-only policy plus the demo database credentials) for 2 hours.
        let credentials = app.switches["extension-db-demo"]
        XCTAssertTrue(reveal(credentials, in: app), "The demo credentials toggle can be reached.")
        setSwitch(credentials, on: true)
        XCTAssertTrue(reveal(review, in: app), "Review & Approve can be reached.")
        review.tap()
        let approve = app.buttons["approveGrant"]
        XCTAssertTrue(approve.waitForExistence(timeout: 10), "The approval sheet opens.")
        settle()
        snapshot("02_Approve")

        // 01: the dashboard with the grant active on the demo build runner.
        approve.tap()
        XCTAssertTrue(approve.waitForNonExistence(timeout: 20), "The approval sheet closes.")
        dismissBanner(in: app)
        scrollToTop(in: app)
        dismissBanner(in: app)
        settle()
        snapshot("01_Dashboard")

        // 04: a direct token with its short-lived database credentials, shown in the app.
        let delivery = app.segmentedControls["demoDeliveryPicker"]
        XCTAssertTrue(reveal(delivery, in: app), "The demo delivery picker can be reached.")
        delivery.buttons.element(boundBy: 1).tap()
        XCTAssertTrue(reveal(review, in: app))
        review.tap()
        XCTAssertTrue(approve.waitForExistence(timeout: 10), "The approval sheet opens for the direct token.")
        settle()
        approve.tap()
        XCTAssertTrue(approve.waitForNonExistence(timeout: 20), "The direct token is minted.")
        scrollToTop(in: app)
        dismissBanner(in: app)
        let revealToken = app.buttons["revealDirectToken"]
        XCTAssertTrue(revealToken.waitForExistence(timeout: 10), "The minted token is shown.")
        revealToken.tap()
        let revealCredentials = app.buttons["revealArtifact-db-creds.json"]
        if revealCredentials.waitForExistence(timeout: 5) {
            revealCredentials.tap()
        }
        scrollToTop(in: app)
        settle()
        snapshot("04_DirectToken")

        // 05: Recent Activity, with the sample history and this session's demo grants.
        XCTAssertTrue(activity.waitForExistence(timeout: 5))
        activity.tap()
        let done = app.buttons["activityDone"]
        XCTAssertTrue(done.waitForExistence(timeout: 5), "Recent Activity opens.")
        settle()
        snapshot("05_Activity")
        done.tap()
        XCTAssertTrue(done.waitForNonExistence(timeout: 5))

        // 03: Settings with the server-scoped approval key.
        settingsTab(in: app).tap()
        let setup = app.buttons["guidedServerSetup"]
        XCTAssertTrue(app.buttons["addServerManually"].waitForExistence(timeout: 10), "Settings opens.")
        scrollToTop(in: app)
        settle()
        snapshot("03_Settings")

        // 06: Guided Server Setup, the first step of adding a server.
        XCTAssertTrue(reveal(setup, in: app), "Guided Server Setup can be reached.")
        setup.tap()
        XCTAssertTrue(app.navigationBars.firstMatch.waitForExistence(timeout: 10), "Setup opens.")
        settle()
        snapshot("06_ServerSetup")
    }

    // MARK: - Helpers

    /// Lets transitions and list layout finish before a capture.
    private func settle() {
        RunLoop.current.run(until: Date().addingTimeInterval(1.0))
    }

    private func setSwitch(_ element: XCUIElement, on: Bool) {
        let knob = element.switches.firstMatch.exists ? element.switches.firstMatch : element
        for _ in 0..<3 where (knob.value as? String) != (on ? "1" : "0") {
            knob.tap()
        }
        XCTAssertEqual(knob.value as? String, on ? "1" : "0")
    }

    private func dismissBanner(in app: XCUIApplication) {
        let dismiss = app.buttons["dismissBanner"]
        if dismiss.waitForExistence(timeout: 3), dismiss.isHittable {
            dismiss.tap()
            _ = dismiss.waitForNonExistence(timeout: 3)
        }
    }

    private func settingsTab(in app: XCUIApplication) -> XCUIElement {
        let tabBar = app.tabBars.firstMatch
        if tabBar.exists, tabBar.buttons.count > 1 {
            return tabBar.buttons.element(boundBy: 1)
        }
        // iPad's floating tab bar names its tabs by their symbol.
        return app.buttons["gearshape"].firstMatch
    }

    private func scroller(in app: XCUIApplication) -> XCUIElement {
        let lists = app.collectionViews.allElementsBoundByIndex.filter { $0.isHittable }
        return lists.last ?? app.collectionViews.firstMatch
    }

    /// The list's leading margin: clear of its rows' controls and of the scroll indicator, which
    /// sits on the trailing edge (the left one in right-to-left languages).
    private var marginX: CGFloat {
        let rightToLeft = ["ar", "he", "fa", "ur"].contains { Snapshot.deviceLanguage.hasPrefix($0) }
        return rightToLeft ? 0.96 : 0.04
    }

    /// Drags in the list's leading margin.
    private func scroll(in app: XCUIApplication, down: Bool) {
        let list = scroller(in: app)
        let start = list.coordinate(withNormalizedOffset: CGVector(dx: marginX, dy: down ? 0.7 : 0.3))
        let end = list.coordinate(withNormalizedOffset: CGVector(dx: marginX, dy: down ? 0.35 : 0.65))
        start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .slow, thenHoldForDuration: 0.2)
    }

    /// Scrolls up until the list stops moving, so every capture starts at the list's top.
    private func scrollToTop(in app: XCUIApplication) {
        let list = scroller(in: app)
        var previous = app.screenshot().pngRepresentation
        for _ in 0..<10 {
            let high = list.coordinate(withNormalizedOffset: CGVector(dx: marginX, dy: 0.2))
            let low = list.coordinate(withNormalizedOffset: CGVector(dx: marginX, dy: 0.9))
            high.press(forDuration: 0.05, thenDragTo: low, withVelocity: .fast, thenHoldForDuration: 0)
            RunLoop.current.run(until: Date().addingTimeInterval(0.6))
            let next = app.screenshot().pngRepresentation
            if next == previous { break }
            previous = next
        }
    }

    /// In view, below the navigation bar and clear of a bottom tab bar or the keyboard.
    private func isRevealed(_ element: XCUIElement, in app: XCUIApplication) -> Bool {
        guard element.exists, element.isHittable else { return false }
        let window = app.windows.firstMatch.frame
        var bottom = window.maxY - 24
        let tabBar = app.tabBars.firstMatch
        if tabBar.exists, tabBar.frame.minY > window.midY {
            bottom = min(bottom, tabBar.frame.minY)
        }
        let keyboard = app.keyboards.firstMatch
        if keyboard.exists, keyboard.frame.height > 0 {
            bottom = min(bottom, keyboard.frame.minY)
        }
        return element.frame.minY >= window.minY + 100 && element.frame.maxY <= bottom
    }

    private func reveal(_ element: XCUIElement, in app: XCUIApplication) -> Bool {
        for _ in 0..<30 {
            if isRevealed(element, in: app) { return true }
            let isAbove = element.exists && element.frame.maxY < scroller(in: app).frame.midY
            scroll(in: app, down: !isAbove)
        }
        return isRevealed(element, in: app)
    }
}
