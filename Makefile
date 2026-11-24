SHELL := /bin/bash
APP_NAME := BaoBuddyHelper.app
BUILD_DIR := build
APP_BUNDLE := $(BUILD_DIR)/$(APP_NAME)
INSTALL_APP := /Applications/$(APP_NAME)
INSTALL_BIN := $(HOME)/.local/bin/bao-buddy
INSTALL_BIN_COMPAT := $(HOME)/.local/bin/bao-grant-helper
# Auto-select an installed Developer ID Application identity when available;
# fall back to ad-hoc signing (`-`) so contributors can build locally out of the box.
# Override anytime with `SIGN_IDENTITY="Developer ID Application: ..."` or `SIGN_IDENTITY="-"`.
SIGN_IDENTITY ?= $(shell id=$$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -n 1); printf '%s' "$${id:--}")
IOS_SIM ?= platform=iOS Simulator,name=iPhone 18 Pro
IPAD_SIM ?= platform=iOS Simulator,name=iPad Pro 13-inch (M5)
# The pinned ios-release platform (northcutted/ios-release-workflows), run locally as PicStrip does.
PLATFORM := bin/ios-release
DEVICE ?=
DEVICES ?=
LANGUAGES ?=
# Local captures get a clean status bar (9:41, full bars, 100% battery); CI leaves it alone.
SCREENSHOT_CLEAN_STATUS_BAR ?= $(if $(CI),0,1)

.PHONY: help brand test-core test-ios build-mac install-mac dist-mac lint clean \
	platform-sync platform-gems platform-images screenshots process-screenshots verify-screenshots clean-screenshots

help:
	@echo "BaoBuddy commands:"
	@echo "  make brand         Regenerate logo, app icon and brand assets from Branding/generate.py"
	@echo "  make test-core     Run BaoBuddyCore SwiftPM unit tests"
	@echo "  make test-ios      Build and test BaoBuddy iOS app on simulator"
	@echo "  make build-mac     Build and sign $(APP_BUNDLE) (Hardened Runtime + Menu Bar)"
	@echo "  make install-mac   Install $(APP_NAME) to /Applications and link ~/.local/bin/bao-buddy"
	@echo "  make dist-mac      Package signed .zip, .dmg, SHA256SUMS.txt, and rendered Homebrew Cask"
	@echo "  make lint          Run SwiftLint"
	@echo "  make clean         Remove build artifacts"
	@echo ""
	@echo "App Store screenshots (pinned ios-release platform, fastlane snapshot):"
	@echo "  make platform-sync         Fetch the pinned platform once (offline afterwards)"
	@echo "  make platform-gems         Install the platform's locked Ruby tools (fastlane) under build/"
	@echo "  make platform-images       Install the locked image tools (Pillow) under build/"
	@echo "  make screenshots           Capture every screen, device and locale from fastlane/Snapfile"
	@echo "  make screenshots DEVICE=\"iPhone 18 Pro Max\" LANGUAGES=\"en-US,de-DE\""
	@echo "                             Capture a device and/or locale subset (DEVICES takes a comma list)"
	@echo "  make process-screenshots   Compose app-store/screenshots from app-store/screenshots-raw"
	@echo "  make verify-screenshots    Check composed screenshot coverage and dimensions"
	@echo "  make clean-screenshots     Remove screenshot logs"

brand:
	python3 Branding/generate.py

test-core:
	swift test --filter BaoBuddyCoreTests

# Set TEST_RESULTS_DIR to keep an .xcresult bundle per destination (CI uploads them on failure).
test-ios:
	xcodebuild test -project BaoBuddy.xcodeproj -scheme BaoBuddy -destination "$(IOS_SIM)" CODE_SIGNING_ALLOWED=NO \
		$(if $(TEST_RESULTS_DIR),-resultBundlePath "$(TEST_RESULTS_DIR)/iphone.xcresult")
	xcodebuild test -project BaoBuddy.xcodeproj -scheme BaoBuddy -destination "$(IPAD_SIM)" CODE_SIGNING_ALLOWED=NO \
		$(if $(TEST_RESULTS_DIR),-resultBundlePath "$(TEST_RESULTS_DIR)/ipad.xcresult")

build-mac:
	swift build -c release --product BaoBuddyHelper --force-resolved-versions
	rm -rf "$(APP_BUNDLE)"
	mkdir -p "$(APP_BUNDLE)/Contents/MacOS" "$(APP_BUNDLE)/Contents/Resources"
	cp .build/release/BaoBuddyHelper "$(APP_BUNDLE)/Contents/MacOS/BaoBuddyHelper"
	cp MacHelper/Info.plist "$(APP_BUNDLE)/Contents/Info.plist"
	# One icon source for iOS and macOS: compile the Icon Composer file to Assets.car + AppIcon.icns.
	xcrun actool BaoBuddy/AppIcon.icon --compile "$(APP_BUNDLE)/Contents/Resources" \
		--platform macosx --minimum-deployment-target 15.0 --app-icon AppIcon \
		--output-partial-info-plist "$(BUILD_DIR)/AppIcon-partial.plist" >/dev/null
	cp MacHelper/MenuBarGlyph*.png "$(APP_BUNDLE)/Contents/Resources/"
	if [ "$(SIGN_IDENTITY)" = "-" ]; then codesign --force --options runtime --sign - "$(APP_BUNDLE)"; else scripts/sign-mac-helper.sh "$(APP_BUNDLE)" "$(SIGN_IDENTITY)" "$(MAC_HELPER_PROFILE)"; fi
	codesign --verify --strict --verbose=2 "$(APP_BUNDLE)"

install-mac: build-mac
	swift scripts/install-mac-helper.swift "$(APP_BUNDLE)" "$(INSTALL_APP)"
	mkdir -p "$(dir $(INSTALL_BIN))"
	ln -sf "$(INSTALL_APP)/Contents/MacOS/BaoBuddyHelper" "$(INSTALL_BIN)"
	ln -sf "$(INSTALL_APP)/Contents/MacOS/BaoBuddyHelper" "$(INSTALL_BIN_COMPAT)"
	@echo "Installed $(INSTALL_APP) -> $(INSTALL_BIN) (and $(INSTALL_BIN_COMPAT))"

dist-mac: build-mac
	@VERSION=$$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$(APP_BUNDLE)/Contents/Info.plist"); \
	ZIP="$(BUILD_DIR)/BaoBuddyHelper-$${VERSION}-macos.zip"; \
	DMG="$(BUILD_DIR)/BaoBuddyHelper-$${VERSION}-macos.dmg"; \
	STAGE="$(BUILD_DIR)/dmg-stage"; \
	rm -rf "$$ZIP" "$$DMG" "$$STAGE"; \
	ditto -c -k --keepParent "$(APP_BUNDLE)" "$$ZIP"; \
	mkdir -p "$$STAGE"; \
	cp -R "$(APP_BUNDLE)" "$$STAGE/"; \
	ln -s /Applications "$$STAGE/Applications"; \
	hdiutil create -volname "BaoBuddy $${VERSION}" -srcfolder "$$STAGE" -ov -format UDZO "$$DMG" >/dev/null; \
	rm -rf "$$STAGE"; \
	(cd "$(BUILD_DIR)" && shasum -a 256 "$$(basename "$$ZIP")" "$$(basename "$$DMG")" > SHA256SUMS.txt); \
	ZIP_SHA=$$(awk -v f="$$(basename "$$ZIP")" '$$2 == f { print $$1 }' "$(BUILD_DIR)/SHA256SUMS.txt"); \
	sed -e "s|__VERSION__|$${VERSION}|g" -e "s|__SHA256__|$${ZIP_SHA}|g" packaging/homebrew/baobuddy.rb > "$(BUILD_DIR)/baobuddy.rb"; \
	echo "Packaged $$ZIP, $$DMG, $(BUILD_DIR)/SHA256SUMS.txt, and $(BUILD_DIR)/baobuddy.rb"

lint:
	swiftlint lint

clean:
	rm -rf "$(BUILD_DIR)" .build

platform-sync:
	$(PLATFORM) sync

platform-gems:
	$(PLATFORM) setup --apple

platform-images:
	$(PLATFORM) setup --images

screenshots:
	SCREENSHOT_CLEAN_STATUS_BAR=$(SCREENSHOT_CLEAN_STATUS_BAR) \
		$(PLATFORM) screenshots-capture --devices "$(if $(DEVICE),$(DEVICE),$(DEVICES))" --languages "$(LANGUAGES)"

process-screenshots:
	$(PLATFORM) screenshots-compose

verify-screenshots:
	$(PLATFORM) screenshots-verify app-store/screenshots --output build/screenshots-manifest.json

clean-screenshots:
	rm -rf fastlane/screenshot_logs app-store/screenshots-raw/test_output app-store/screenshots-raw/screenshots.html
