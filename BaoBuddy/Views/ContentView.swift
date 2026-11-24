import BaoBuddyCore
import SwiftUI

struct ContentView: View {
    @Bindable var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            TabView(selection: $model.selectedTab) {
                DashboardView(model: model)
                    .tabItem {
                        Label("Grants", image: "BaoBuddyGlyph")
                    }
                    .tag(0)

                SettingsView(model: model)
                    .tabItem {
                        Label("Settings", systemImage: "gearshape")
                    }
                    .tag(1)
            }
            .tint(BaoTheme.brand)
            .sheet(
                isPresented: Binding(
                    get: { model.pendingRequest != nil },
                    set: { presented in
                        if !presented { model.dismissApproval() }
                    }
                )
            ) {
                // The sheet shows the profile the request was parsed against, which may differ
                // from the active one when a link named another server.
                if let profile = model.pendingProfile, let request = model.pendingRequest {
                    ApprovalSheetView(model: model, profile: profile, request: request)
                        .presentationSizing(.form)
                }
            }
            .sheet(item: $model.pendingImportedProfile) { incoming in
                ConfirmProfileImportSheet(
                    profile: incoming,
                    plan: model.pendingImport,
                    onConfirm: { model.confirmPendingImportedProfile() },
                    onCancel: { model.cancelPendingImport() }
                )
                .presentationSizing(.form)
            }

            // App-switcher privacy shield so tokens and server details never leak into snapshots.
            if scenePhase != .active {
                ZStack {
                    Rectangle()
                        .fill(.regularMaterial)
                        .ignoresSafeArea()
                    VStack(spacing: 12) {
                        BaoBuddyEmblem(tint: BaoTheme.brand, size: 64)
                        Text(verbatim: "BaoBuddy")
                            .font(.title.weight(.semibold))
                            .foregroundStyle(.secondary)
                    }
                }
                .transition(.opacity)
            }
        }
    }
}
