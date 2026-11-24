import UIKit
import XCTest

/// Xcode's accessibility audits on BaoBuddy's main screens: the evidence behind
/// app-store/accessibility_declarations.json.
///
/// At the largest accessibility text size (in dark) every audit type runs.
/// At the default size (in light) the audits that depend on size there — hit
/// regions, labels, traits, text left out of the accessibility tree — run;
/// Dynamic Type and clipping are measured at the largest size, where they show.
/// Contrast findings are attached, not failed: BaoBuddy does not claim
/// Sufficient Contrast (its orange and green status colours and secondary text
/// are the system's).  Anything else fails unless it is a reviewed exception
/// (`acceptedReason`).
///
/// A screen that scrolls is audited at its top and its end.  Every page of it
/// is audited with `TEST_RUNNER_BAOBUDDY_AUDIT_EVERY_SCREEN=1` in xcodebuild's
/// environment.
@MainActor
final class AccessibilityAuditTests: XCTestCase {
    private static let auditsEveryScreen = ProcessInfo.processInfo.environment["BAOBUDDY_AUDIT_EVERY_SCREEN"] == "1"

    private var contrastFindings: [String] = []
    /// The launch's text size, as it is named in failures and screenshots.
    private var textSize = ""
    /// The launch's appearance: dark at the largest size, light at the default.
    private var appearance = XCUIDevice.Appearance.light
    private var isLargestText = false

    override func setUpWithError() throws {
        // One screen's findings must not hide the next screen's.
        continueAfterFailure = true
    }

    override func tearDown() async throws {
        if !contrastFindings.isEmpty {
            let report = XCTAttachment(string: contrastFindings.joined(separator: "\n"))
            report.name = "Contrast findings (not failed)"
            report.lifetime = .keepAlways
            add(report)
        }
        XCUIDevice.shared.appearance = .light
        try await super.tearDown()
    }

    // MARK: - Tests

    /// Welcome (no server yet) and Guided Server Setup.
    func testWelcomeScreensAtDefaultTextSize() {
        auditWelcomeFlow(launch(largestText: false, arguments: ["-BaoBuddyEmptyOnboarding"]))
    }

    func testWelcomeScreensAtLargestTextSize() {
        auditWelcomeFlow(launch(largestText: true, arguments: ["-BaoBuddyEmptyOnboarding"]))
    }

    /// Grants (idle and with an active grant), both approval sheets, Recent
    /// Activity, Settings, the server editor and Help, in Demo Mode.
    func testDemoScreensAtDefaultTextSize() {
        auditDemoFlow(launch(largestText: false, arguments: ["-BaoBuddyDemo"]))
    }

    func testDemoScreensAtLargestTextSize() {
        auditDemoFlow(launch(largestText: true, arguments: ["-BaoBuddyDemo"]))
    }

    // MARK: - Flows

    private func auditWelcomeFlow(_ app: XCUIApplication) {
        XCTAssertTrue(app.buttons["Try Demo"].waitForExistence(timeout: 15), "Welcome opens.")
        auditScrolling("Welcome", until: app.staticTexts.matching(Self.labelContains("in Terminal")).firstMatch, in: app)

        let setup = app.buttons["Guided Server Setup"]
        XCTAssertTrue(reveal(setup, in: app), "Guided Server Setup can be reached.")
        setup.tap()
        let cancel = app.navigationBars.buttons["Cancel"]
        XCTAssertTrue(cancel.waitForExistence(timeout: 5), "Setup opens.")
        auditScrolling("Guided Server Setup", until: app.staticTexts.matching(Self.labelContains("Best if")).firstMatch, in: app)
        cancel.tap()
    }

    private func auditDemoFlow(_ app: XCUIApplication) {
        let review = app.buttons["Review & Approve"]
        if !app.staticTexts["Demo OpenBao"].waitForExistence(timeout: 15) {
            // The first launch after installing has come up without its launch
            // arguments (on the welcome screen); a second launch has them.
            app.terminate()
            app.launch()
        }
        XCTAssertTrue(app.staticTexts["Demo OpenBao"].waitForExistence(timeout: 15), "Grants opens in Demo Mode.")
        auditScrolling("Grants", until: review, in: app)

        // A standard grant: the default read-only policy.
        XCTAssertTrue(reveal(review, in: app), "Review & Approve can be reached.")
        review.tap()
        let approve = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Approve'")).firstMatch
        XCTAssertTrue(approve.waitForExistence(timeout: 5), "The approval sheet opens.")
        XCTAssertTrue(app.staticTexts["Standard Grant"].exists, "The sheet says the grant is standard.")
        let payload = app.staticTexts["auditPayload"]
        auditScrolling("Approve, standard", until: payload, in: app)
        approve.tap()

        // Demo Mode signs with an in-memory key, so no Face ID prompt appears.
        let revoke = app.buttons["Revoke Grant"]
        let granted = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Granted until'")).firstMatch
        XCTAssertTrue(approve.waitForNonExistence(timeout: 15), "The approval sheet closes.")
        // The banner is the list's first row, which a lazy list loads only near the top.
        scrollToTop(in: app)
        XCTAssertTrue(granted.waitForExistence(timeout: 15), "The grant becomes active.")
        auditScrolling("Grants, active grant", until: revoke, in: app)

        // An elevated grant: add the elevated Kubernetes policy.
        let elevatedPolicy = app.switches.matching(NSPredicate(format: "label BEGINSWITH 'Kubernetes Deploy'")).firstMatch
        XCTAssertTrue(reveal(elevatedPolicy, in: app), "The elevated policy can be reached.")
        let knob = elevatedPolicy.switches.firstMatch.exists ? elevatedPolicy.switches.firstMatch : elevatedPolicy
        for _ in 0..<3 where (knob.value as? String) != "1" {
            knob.tap()
        }
        XCTAssertEqual(knob.value as? String, "1", "The elevated policy is selected.")
        XCTAssertTrue(reveal(review, in: app))
        review.tap()
        XCTAssertTrue(app.staticTexts["Elevated Grant"].waitForExistence(timeout: 5), "The sheet says the grant is elevated.")
        auditScrolling("Approve, elevated", until: payload, in: app)
        app.navigationBars.buttons["Cancel"].tap()

        scrollToTop(in: app)
        let activity = app.buttons["Activity"]
        XCTAssertTrue(activity.waitForExistence(timeout: 5))
        activity.tap()
        let done = app.navigationBars.buttons["Done"]
        XCTAssertTrue(done.waitForExistence(timeout: 5), "Recent Activity opens.")
        audit("Recent Activity", in: app)
        done.tap()

        settingsTab(in: app).tap()
        let help = app.buttons["Help & About"]
        XCTAssertTrue(app.staticTexts["Demo OpenBao"].waitForExistence(timeout: 5), "Settings opens.")
        auditScrolling("Settings", until: help, in: app)

        scrollToTop(in: app)
        let addServer = app.buttons["Add Server Manually…"]
        XCTAssertTrue(reveal(addServer, in: app), "Add Server Manually can be reached.")
        addServer.tap()
        let cancel = app.navigationBars.buttons["Cancel"]
        XCTAssertTrue(cancel.waitForExistence(timeout: 5), "The server editor opens.")
        auditScrolling("Server editor", until: app.switches["Deliver Grants Over SSH"], in: app)
        cancel.tap()

        XCTAssertTrue(reveal(help, in: app), "Help & About can be reached.")
        help.tap()
        XCTAssertTrue(done.waitForExistence(timeout: 5), "Help opens.")
        auditScrolling("Help & About", until: app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Copy Diagnostics'")).firstMatch,
                       in: app)
        done.tap()
    }

    // MARK: - Launching

    /// Default size in light; the largest accessibility size in dark.
    private func launch(largestText: Bool, arguments: [String]) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = arguments + ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        if largestText {
            app.launchArguments += [
                "-UIPreferredContentSizeCategoryName", UIContentSizeCategory.accessibilityExtraExtraExtraLarge.rawValue
            ]
        }
        appearance = largestText ? .dark : .light
        XCUIDevice.shared.appearance = appearance
        textSize = largestText ? "largest text" : "default text"
        isLargestText = largestText
        app.launch()
        return app
    }

    // MARK: - Auditing

    private func audit(_ screen: String, in app: XCUIApplication, file: StaticString = #filePath, line: UInt = #line) {
        // Let transitions finish: a control caught mid-animation reads as clipped.
        Thread.sleep(forTimeInterval: 0.6)
        let name = "\(screen) (\(textSize), \(appearance == .dark ? "dark" : "light"))"
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
        let types: XCUIAccessibilityAuditType = isLargestText ? .all : .all.subtracting([.dynamicType, .textClipped])
        // The audit has a time limit of its own (about 15 s), and a busy CI
        // simulator can run past it, which checks nothing.  The retry leaves out
        // contrast: it is the slowest check, and its findings never fail the test.
        do {
            try audit(types, name: name, in: app, file: file, line: line)
        } catch let error as NSError where Self.isAuditTimeout(error) && types.contains(.contrast) {
            contrastFindings.append("\(name): not checked — the audit ran out of time")
            XCTContext.runActivity(named: "\(name): the audit ran out of time; trying again without contrast") { _ in }
            do {
                try audit(types.subtracting(.contrast), name: name, in: app, file: file, line: line)
            } catch {
                XCTFail("\(name): the audit could not run: \(error)", file: file, line: line)
            }
        } catch {
            XCTFail("\(name): the audit could not run: \(error)", file: file, line: line)
        }
    }

    private func audit(
        _ types: XCUIAccessibilityAuditType, name: String, in app: XCUIApplication, file: StaticString, line: UInt
    ) throws {
        try app.performAccessibilityAudit(for: types) { issue in
            if issue.auditType == .contrast {
                self.contrastFindings.append("\(name): \(issue.compactDescription)")
                return true
            }
            // One snapshot per issue: each property of a live element is a query of its own.
            let element = try? issue.element?.snapshot()
            let description = Self.describe(issue, element)
            if let reason = self.acceptedReason(for: issue, element, on: name, in: app) {
                XCTContext.runActivity(named: "Accepted on \(name): \(description) — \(reason)") { _ in }
            } else {
                XCTFail("\(name): \(description)", file: file, line: line)
            }
            return true
        }
    }

    /// "Audit failed to complete in time" or "Timed out while running accessibility
    /// audit" (XCTest has no public constants for them).
    private static func isAuditTimeout(_ error: NSError) -> Bool {
        (error.domain == "com.apple.xcode.xctest.accessibilityAudit" && error.code == -56)
            || (error.domain == "com.apple.dt.XCTest.XCTFuture" && error.code == 1000)
    }

    private static func describe(_ issue: XCUIAccessibilityAuditIssue, _ element: (any XCUIElementSnapshot)?) -> String {
        var text = "\(issue.compactDescription) [\(issue.detailedDescription)]"
        if let element {
            text += " — \(element.elementType) “\(element.label)”"
            if !element.identifier.isEmpty { text += " #\(element.identifier)" }
            text += " \(element.frame.integral)"
        }
        return text
    }

    /// Reviewed findings that are not defects, each with why.  Everything else fails.
    private func acceptedReason(
        for issue: XCUIAccessibilityAuditIssue, _ element: (any XCUIElementSnapshot)?, on name: String, in app: XCUIApplication
    ) -> String? {
        let isPartial = issue.compactDescription.localizedCaseInsensitiveContains("partially")
        switch issue.auditType {
        case .dynamicType where isPartial && element.map({ isNavigationBarButton($0, in: app) }) == true:
            return "System bar buttons stop growing and show the Large Content Viewer on touch and hold."
        case .dynamicType where isPartial && element.map(Self.isDrawnLarge) == true:
            return "Text the audit calls partly scaled that is drawn 40 pt tall or more at this size, as the "
                + "screenshot shows."
        case .textClipped where element.map(Self.isWrappedText) == true:
            return "Text that wraps over two or more lines, beneath its row's icon at this size; the screenshot "
                + "shows every line in full (nothing in the app limits these to fewer lines)."
        case .dynamicType where element == nil, .textClipped where element == nil:
            if !issue.detailedDescription.contains("SwiftUI") {
                return "UIKit bar text (the inline navigation bar title, or the iPad tab bar's tabs), which keeps "
                    + "its size like all system bars and shows the Large Content Viewer (see the screenshot)."
            }
            if name.contains(", page ") {
                return "A row cut by a bar at an arbitrary scroll position; the audit cannot name it, and the "
                    + "overlapping pages before and after audit it whole (see the screenshots)."
            }
        case .elementDetection where element == nil && UIDevice.current.userInterfaceIdiom == .pad
            && Self.sheetScreens.contains(where: name.hasPrefix):
            return "On iPad the sheet floats over the dimmed screen it came from; the audit reads that screen's text, "
                + "which VoiceOver rightly leaves out while the sheet is open."
        case .elementDetection where element == nil && Self.tabScreens.contains(where: name.hasPrefix):
            return "Text scrolled beneath the floating Liquid Glass tab bar shows through it; that text is "
                + "an accessibility element of the list, and VoiceOver reads it."
        default:
            break
        }
        return nil
    }

    /// The tab bar's own screens, whose lists scroll beneath it.
    private static let tabScreens = ["Grants", "Settings"]

    /// Text the audit calls partly scaled though it is drawn at the largest size:
    /// at least 40 pt tall, which text that ignored Dynamic Type (about 11 to 20 pt
    /// a line by default) would not reach.  The screenshots show these at full size:
    /// the status pills, Settings' server summary line, and the approve button's
    /// title on iPad.
    private static func isDrawnLarge(_ element: any XCUIElementSnapshot) -> Bool {
        element.elementType == .staticText && element.frame.height >= 40
    }

    /// Static text at least two lines of the largest size tall, which wraps rather than truncates.
    private static func isWrappedText(_ element: any XCUIElementSnapshot) -> Bool {
        element.elementType == .staticText && element.frame.height >= 110
    }

    /// Screens presented as sheets, which on iPad float over the screen they came from.
    private static let sheetScreens = ["Approve, ", "Recent Activity", "Server editor", "Help & About", "Guided Server Setup"]

    private func isNavigationBarButton(_ element: any XCUIElementSnapshot, in app: XCUIApplication) -> Bool {
        guard element.elementType == .button else { return false }
        return app.navigationBars.allElementsBoundByIndex.contains { $0.frame.contains(element.frame) }
    }

    // MARK: - Helpers

    private static func labelContains(_ text: String) -> NSPredicate {
        NSPredicate(format: "label CONTAINS %@", text)
    }

    private func settingsTab(in app: XCUIApplication) -> XCUIElement {
        let tab = app.tabBars.buttons["Settings"]
        return tab.exists ? tab : app.buttons["Settings"].firstMatch
    }

    /// Audits a scrolling screen from its top until `last` is in view: every
    /// page when auditing every screen, otherwise the first and the last.
    private func auditScrolling(_ screen: String, until last: XCUIElement, in app: XCUIApplication,
                                file: StaticString = #filePath, line: UInt = #line) {
        audit(screen, in: app, file: file, line: line)
        var atEnd = isRevealed(last, in: app)
        var page = 1
        var view = app.screenshot().pngRepresentation
        while !atEnd, page < 60 {
            page += 1
            // Page by page to audit each; otherwise flung, since only the end is audited.
            scroll(in: app, down: true, fling: !Self.auditsEveryScreen)
            atEnd = isRevealed(last, in: app)
            // A drag that moves nothing means the list is at its end without `last`.
            let next = app.screenshot().pngRepresentation
            if next == view { break }
            view = next
            if Self.auditsEveryScreen || atEnd {
                audit(atEnd ? "\(screen), end" : "\(screen), page \(page)", in: app, file: file, line: line)
            }
        }
        if !atEnd {
            let tree = XCTAttachment(string: app.debugDescription)
            tree.name = "\(screen): elements when the end was not reached"
            tree.lifetime = .keepAlways
            add(tree)
            XCTFail("\(screen): the end of the screen can be reached.", file: file, line: line)
        }
    }

    /// The largest list or scroll view in front: a sheet's rather than the
    /// screen's behind it, which the sheet covers.
    private func scroller(in app: XCUIApplication) -> XCUIElement {
        let lists = app.collectionViews.allElementsBoundByIndex + app.scrollViews.allElementsBoundByIndex
        return lists.filter { $0.exists && $0.isHittable }
            .max { $0.frame.width * $0.frame.height < $1.frame.width * $1.frame.height } ?? app
    }

    /// Drags along the leading margin, slowly so the list does not fling past a page.
    /// Not the trailing one: a drag there can catch the scroll indicator, which
    /// scrolls a long list the other way.
    private func scroll(in app: XCUIApplication, down: Bool, fling: Bool = false) {
        let list = scroller(in: app)
        let x = edgeX(of: list)
        let low = list.coordinate(withNormalizedOffset: CGVector(dx: x, dy: 0.75))
        let high = list.coordinate(withNormalizedOffset: CGVector(dx: x, dy: 0.25))
        let (from, to) = down ? (low, high) : (high, low)
        if fling {
            from.press(forDuration: 0.05, thenDragTo: to, withVelocity: .fast, thenHoldForDuration: 0)
            Thread.sleep(forTimeInterval: 0.8)
        } else {
            from.press(forDuration: 0.05, thenDragTo: to, withVelocity: .slow, thenHoldForDuration: 0.2)
        }
    }

    /// Flings the list back to its top, along the leading margin, where a drag
    /// cannot catch a control.
    private func scrollToTop(in app: XCUIApplication) {
        let list = scroller(in: app)
        let x = edgeX(of: list)
        for _ in 0..<8 {
            let high = list.coordinate(withNormalizedOffset: CGVector(dx: x, dy: 0.2))
            let low = list.coordinate(withNormalizedOffset: CGVector(dx: x, dy: 0.9))
            high.press(forDuration: 0.05, thenDragTo: low, withVelocity: .fast, thenHoldForDuration: 0)
        }
    }

    /// Where to drag: a list's leading margin, clear of its rows' controls; the
    /// middle of a scroll view, whose empty margins do not take touches.
    private func edgeX(of scroller: XCUIElement) -> CGFloat {
        scroller.elementType == .scrollView ? 0.5 : 0.04
    }

    /// In view and clear of the screen's bottom edge, where a tap can be taken
    /// for the home gesture.
    private func isRevealed(_ element: XCUIElement, in app: XCUIApplication) -> Bool {
        guard element.exists, element.isHittable else { return false }
        return element.frame.maxY <= app.windows.firstMatch.frame.maxY - 24
    }

    /// Scrolls the list holding `element` until it can be tapped.
    @discardableResult
    private func reveal(_ element: XCUIElement, in app: XCUIApplication) -> Bool {
        for _ in 0..<40 {
            if isRevealed(element, in: app) { return true }
            let isAbove = element.exists && element.frame.maxY < scroller(in: app).frame.midY
            scroll(in: app, down: !isAbove)
        }
        return isRevealed(element, in: app)
    }
}
