import UIKit
import XCTest

final class IPadLayoutUITests: XCTestCase {
    private static let maxReadableColumnWidth: CGFloat = 740
    private static let widthTolerance: CGFloat = 20
    private static let centerTolerance: CGFloat = 8

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    private func requireIPad() throws {
        let isPad = UIDevice.current.userInterfaceIdiom == .pad
        try XCTSkipUnless(isPad, "iPad-only layout test")
    }

    @MainActor
    func testGrantsTabIPadLayoutMarginScrollTitlesAndHittability() throws {
        try requireIPad()

        let app = XCUIApplication()
        app.launchArguments = ["-BaoBuddyDemo"]
        app.launch()

        verifyGrantsTabLayoutAndMarginScroll(in: app, orientationLabel: "portrait")
    }

    @MainActor
    func testGrantsTabIPadLandscapeLayoutAndMarginScroll() throws {
        try requireIPad()

        let app = XCUIApplication()
        app.launchArguments = ["-BaoBuddyDemo"]
        app.launch()
        defer { restorePortrait(in: app) }

        let demoCardCell = cell(containingText: "Demo OpenBao", in: app)
        XCTAssertTrue(demoCardCell.waitForExistence(timeout: 10), "Demo OpenBao row should load before rotating")

        rotateToLandscapeAndSettle(row: demoCardCell, in: app)
        verifyGrantsTabLayoutAndMarginScroll(in: app, orientationLabel: "landscape")
    }

    @MainActor
    func testSettingsTabIPadLayoutTitlesDeviceClaimAndLandscapeMarginScroll() throws {
        try requireIPad()

        let app = XCUIApplication()
        app.launchArguments = ["-BaoBuddyDemo", "-BaoBuddyDemoScreen", "03_Settings"]
        app.launch()
        defer { restorePortrait(in: app) }

        let navBar = app.navigationBars["Settings"]
        XCTAssertTrue(navBar.waitForExistence(timeout: 10), "Settings navigation bar should exist for VoiceOver and system chrome")

        let demoServerCell = cell(containingText: "Demo OpenBao", in: app)
        XCTAssertTrue(demoServerCell.waitForExistence(timeout: 10), "Demo OpenBao server row should exist in Settings")

        let window = app.windows.firstMatch
        XCTAssertTrue(window.exists)
        waitForFrameToSettle(element: demoServerCell, in: window)

        let titleElement = assertSingleColumnTitle(named: "Settings", in: app, navBar: navBar)
        XCTAssertTrue(demoServerCell.isHittable, "Top Settings row must be hittable (not covered by navigation toolbar)")
        assertCenteredReadableColumn(element: demoServerCell, in: window, context: "Settings portrait Demo OpenBao row")
        XCTAssertEqual(
            titleElement.frame.minX,
            demoServerCell.frame.minX,
            accuracy: 24,
            "In-list Settings title should align with the readable column"
        )

        let scrollContainer = primaryScrollContainer(in: app)
        XCTAssertTrue(scrollContainer.exists, "Settings list scroll container should exist")
        XCTAssertEqual(
            scrollContainer.frame.width,
            window.frame.width,
            accuracy: 2,
            "Settings list should span the full window width so side margins scroll and indicator sits at the screen edge"
        )

        let deviceClaimField = app.textFields.matching(NSPredicate(format: "value == %@", "ipad")).firstMatch
        XCTAssertTrue(deviceClaimField.waitForExistence(timeout: 5), "Device Claim should default to ipad on iPad in demo mode")

        // Rotate to landscape so Settings deterministically overflows vertically on all iPad sizes
        // (including 13-inch iPad where portrait height fits Settings without scrolling) and margins widen.
        rotateToLandscapeAndSettle(row: demoServerCell, in: app)

        let landscapeWindow = app.windows.firstMatch
        let landscapeTitle = assertSingleColumnTitle(named: "Settings", in: app, navBar: navBar)
        XCTAssertTrue(demoServerCell.isHittable, "Top Settings row must remain hittable in landscape")
        assertCenteredReadableColumn(element: demoServerCell, in: landscapeWindow, context: "Settings landscape Demo OpenBao row")
        XCTAssertEqual(
            landscapeTitle.frame.minX,
            demoServerCell.frame.minX,
            accuracy: 24,
            "In-list Settings title should align with the readable column in landscape"
        )
        XCTAssertEqual(
            primaryScrollContainer(in: app).frame.width,
            landscapeWindow.frame.width,
            accuracy: 2,
            "Settings list should remain full width in landscape"
        )

        assertMarginScrollMoved(
            row: demoServerCell,
            fallbackLowerElement: app.buttons["Help & About"],
            in: app,
            window: landscapeWindow,
            context: "Settings-landscape"
        )
    }

    @MainActor
    func testOnboardingIPadLayoutTitlesAndHittability() throws {
        try requireIPad()

        let app = XCUIApplication()
        app.launchArguments = ["-BaoBuddyEmptyOnboarding"]
        app.launch()

        let navBar = app.navigationBars["BaoBuddy"]
        XCTAssertTrue(navBar.waitForExistence(timeout: 10), "Onboarding navigation bar should keep the BaoBuddy title")

        let heading = app.staticTexts["Connect OpenBao or Vault"]
        XCTAssertTrue(heading.waitForExistence(timeout: 10), "Onboarding heading should appear")
        XCTAssertTrue(heading.isHittable, "Onboarding heading must not be covered by navigation toolbar")

        let tryDemoButton = app.buttons["Try Demo"]
        XCTAssertTrue(tryDemoButton.waitForExistence(timeout: 5), "Try Demo button should exist on onboarding")
        XCTAssertTrue(tryDemoButton.isHittable, "Try Demo button must be hittable")

        let window = app.windows.firstMatch
        XCTAssertTrue(window.exists)
        waitForFrameToSettle(element: tryDemoButton, in: window)

        XCTAssertEqual(
            tryDemoButton.frame.midX,
            window.frame.midX,
            accuracy: Self.centerTolerance,
            "Try Demo button should be centered in the window"
        )
        XCTAssertLessThanOrEqual(
            tryDemoButton.frame.width,
            Self.maxReadableColumnWidth + Self.widthTolerance,
            "Try Demo button should fit within the 740pt readable column"
        )

        let scrollView = app.scrollViews.firstMatch
        XCTAssertTrue(scrollView.waitForExistence(timeout: 5), "Onboarding ScrollView should exist")
        XCTAssertEqual(
            scrollView.frame.width,
            window.frame.width,
            accuracy: 2,
            "Onboarding ScrollView should span the full window width"
        )
    }

    // MARK: - Helpers

    @MainActor
    private func verifyGrantsTabLayoutAndMarginScroll(in app: XCUIApplication, orientationLabel: String) {
        let navBar = app.navigationBars["Grants"]
        XCTAssertTrue(navBar.waitForExistence(timeout: 10), "Grants navigation bar should exist in \(orientationLabel)")

        let demoCardCell = cell(containingText: "Demo OpenBao", in: app)
        XCTAssertTrue(demoCardCell.waitForExistence(timeout: 10), "Demo OpenBao row should exist in \(orientationLabel)")

        let window = app.windows.firstMatch
        XCTAssertTrue(window.exists)
        waitForFrameToSettle(element: demoCardCell, in: window)

        let titleElement = assertSingleColumnTitle(named: "Grants", in: app, navBar: navBar)
        XCTAssertTrue(demoCardCell.isHittable, "Top list row must be hittable in \(orientationLabel)")
        assertCenteredReadableColumn(element: demoCardCell, in: window, context: "Grants (\(orientationLabel)) Demo OpenBao row")
        XCTAssertEqual(
            titleElement.frame.minX,
            demoCardCell.frame.minX,
            accuracy: 24,
            "In-list Grants title should align with the readable column in \(orientationLabel)"
        )

        let scrollContainer = primaryScrollContainer(in: app)
        XCTAssertEqual(
            scrollContainer.frame.width,
            window.frame.width,
            accuracy: 2,
            "Grants list should span full window width in \(orientationLabel)"
        )

        let reviewButton = app.buttons["Review & Approve"]
        assertMarginScrollMoved(
            row: demoCardCell,
            fallbackLowerElement: reviewButton,
            in: app,
            window: window,
            context: "Grants-\(orientationLabel)"
        )

        if reviewButton.waitForExistence(timeout: 2), reviewButton.isHittable {
            assertCenteredReadableColumn(element: reviewButton, in: window, context: "Review & Approve (\(orientationLabel))")
        }
    }

    /// Waits for `element` and `window` frames to stop changing across consecutive samples, ensuring
    /// initial `onGeometryChange` content-margin layout and rotation animations have fully completed.
    @MainActor
    private func waitForFrameToSettle(
        element: XCUIElement,
        in window: XCUIElement,
        requireCentered: Bool = true,
        timeout: TimeInterval = 5
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        var lastElementFrame: CGRect?
        var lastWindowFrame: CGRect?
        var stableSamples = 0

        while Date() < deadline {
            if element.exists && window.exists {
                let ef = element.frame
                let wf = window.frame
                let centeredOK = !requireCentered || abs(ef.midX - wf.midX) <= Self.centerTolerance
                if ef.width > 0, wf.width > 0, element.isHittable, centeredOK,
                   let prevE = lastElementFrame, let prevW = lastWindowFrame,
                   framesClose(ef, prevE), framesClose(wf, prevW) {
                    stableSamples += 1
                    if stableSamples >= 3 {
                        return
                    }
                } else {
                    stableSamples = 0
                }
                lastElementFrame = ef
                lastWindowFrame = wf
            } else {
                stableSamples = 0
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.15))
        }
    }

    private func framesClose(_ lhs: CGRect, _ rhs: CGRect) -> Bool {
        abs(lhs.minX - rhs.minX) < 0.5 &&
        abs(lhs.minY - rhs.minY) < 0.5 &&
        abs(lhs.width - rhs.width) < 0.5 &&
        abs(lhs.height - rhs.height) < 0.5
    }

    @MainActor
    private func restorePortrait(in app: XCUIApplication) {
        XCUIDevice.shared.orientation = .portrait
        let window = app.windows.firstMatch
        let deadline = Date().addingTimeInterval(5)
        var stableSamples = 0
        var lastFrame: CGRect?
        while Date() < deadline {
            if window.exists {
                let frame = window.frame
                if frame.height > frame.width, let prev = lastFrame, framesClose(frame, prev) {
                    stableSamples += 1
                    if stableSamples >= 2 {
                        return
                    }
                } else {
                    stableSamples = 0
                }
                lastFrame = frame
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.15))
        }
    }

    @MainActor
    private func rotateToLandscapeAndSettle(row: XCUIElement, in app: XCUIApplication) {
        XCUIDevice.shared.orientation = .landscapeLeft
        let window = app.windows.firstMatch
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline {
            if window.exists && window.frame.width > window.frame.height {
                break
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        XCTAssertGreaterThan(
            window.frame.width,
            window.frame.height,
            "Simulator should rotate to landscape (frame=\(window.frame))"
        )
        waitForFrameToSettle(element: row, in: window, requireCentered: true, timeout: 6)
    }

    @MainActor
    private func assertMarginScrollMoved(
        row: XCUIElement,
        fallbackLowerElement: XCUIElement,
        in app: XCUIApplication,
        window: XCUIElement,
        context: String
    ) {
        waitForFrameToSettle(element: row, in: window)
        let beforeFrame = row.frame
        let marginX = dragUpInLeftMargin(of: window, columnMinX: beforeFrame.minX)

        // Poll for the scrolled frame rather than taking one immediate snapshot.
        let deadline = Date().addingTimeInterval(3)
        var scrolled = false
        var lastFrame: CGRect? = beforeFrame
        while Date() < deadline {
            if row.exists {
                let current = row.frame
                lastFrame = current
                if current.minY < beforeFrame.minY - 30 {
                    scrolled = true
                    break
                }
            } else if fallbackLowerElement.exists {
                lastFrame = nil
                scrolled = true
                break
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }

        if !scrolled {
            attachDiagnostics(
                name: "margin-scroll-failure-\(context)",
                app: app,
                note: "context=\(context) window=\(window.frame) marginX=\(marginX) before=\(beforeFrame) after=\(String(describing: lastFrame))"
            )
            XCTFail(
                "Dragging upward in the left side margin must scroll \(context) " +
                "(marginX=\(marginX), before=\(beforeFrame.minY), after=\(lastFrame.map { "\($0.minY)" } ?? "not-found"))"
            )
        }
    }

    @MainActor
    private func attachDiagnostics(name: String, app: XCUIApplication, note: String) {
        let screenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screenshot.name = "\(name)-screenshot"
        screenshot.lifetime = .keepAlways
        add(screenshot)

        let hierarchy = XCTAttachment(string: "\(note)\n\n\(app.debugDescription)")
        hierarchy.name = "\(name)-hierarchy.txt"
        hierarchy.lifetime = .keepAlways
        add(hierarchy)
    }

    @MainActor
    private func cell(containingText text: String, in app: XCUIApplication) -> XCUIElement {
        let predicate = NSPredicate(format: "label == %@", text)
        return app.cells.containing(.staticText, identifier: text).firstMatch.exists
            ? app.cells.containing(.staticText, identifier: text).firstMatch
            : app.cells.containing(predicate).firstMatch
    }

    @MainActor
    private func primaryScrollContainer(in app: XCUIApplication) -> XCUIElement {
        if app.collectionViews.firstMatch.exists {
            return app.collectionViews.firstMatch
        }
        return app.scrollViews.firstMatch
    }

    @MainActor
    @discardableResult
    private func assertSingleColumnTitle(
        named title: String,
        in app: XCUIApplication,
        navBar: XCUIElement
    ) -> XCUIElement {
        let navBarStaticTitles = navBar.staticTexts.matching(NSPredicate(format: "label == %@", title))
            .allElementsBoundByIndex
            .filter { $0.exists && $0.frame.height > 1 && $0.isHittable }
        XCTAssertTrue(
            navBarStaticTitles.isEmpty,
            "Navigation bar should not display a duplicate visible inline '\(title)' title on iPad"
        )

        let scrollContainer = primaryScrollContainer(in: app)
        XCTAssertTrue(scrollContainer.waitForExistence(timeout: 5))
        let contentTitles = scrollContainer.staticTexts.matching(NSPredicate(format: "label == %@", title))
            .allElementsBoundByIndex
            .filter { $0.exists && $0.frame.height > 1 }
        XCTAssertEqual(
            contentTitles.count,
            1,
            "Expected exactly one visible '\(title)' heading in the content column, found \(contentTitles.count)"
        )
        return contentTitles.first ?? scrollContainer.staticTexts[title].firstMatch
    }

    @MainActor
    private func assertCenteredReadableColumn(
        element: XCUIElement,
        in window: XCUIElement,
        context: String
    ) {
        let frame = element.frame
        let windowFrame = window.frame
        XCTAssertEqual(
            frame.midX,
            windowFrame.midX,
            accuracy: Self.centerTolerance,
            "\(context) should be horizontally centered (element midX=\(frame.midX), window midX=\(windowFrame.midX))"
        )
        XCTAssertLessThanOrEqual(
            frame.width,
            Self.maxReadableColumnWidth + Self.widthTolerance,
            "\(context) width (\(frame.width)) should be at most \(Self.maxReadableColumnWidth) + tolerance"
        )
        XCTAssertGreaterThan(frame.width, 200, "\(context) width should not be collapsed")
    }

    @MainActor
    @discardableResult
    private func dragUpInLeftMargin(of window: XCUIElement, columnMinX: CGFloat) -> CGFloat {
        let windowWidth = max(window.frame.width, 1)
        let preferredX = windowWidth * 0.04
        // Stay strictly inside the empty left margin while avoiding the system screen-edge gesture zone.
        let safeMarginX: CGFloat
        if columnMinX > 24 {
            safeMarginX = min(preferredX, max(14, columnMinX * 0.5))
        } else {
            safeMarginX = max(10, columnMinX * 0.6)
        }
        let normalizedX = safeMarginX / windowWidth
        let start = window.coordinate(withNormalizedOffset: CGVector(dx: normalizedX, dy: 0.64))
        let end = window.coordinate(withNormalizedOffset: CGVector(dx: normalizedX, dy: 0.40))
        // Touch-down 10ms + 250 pt/s steady pan + brief end hold avoids both long-press misclassification
        // on loaded simulators and inertial fling that recycles top cells out of the viewport.
        start.press(
            forDuration: 0.01,
            thenDragTo: end,
            withVelocity: XCUIGestureVelocity(250),
            thenHoldForDuration: 0.15
        )
        return safeMarginX
    }
}
