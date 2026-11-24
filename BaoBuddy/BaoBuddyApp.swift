import BaoBuddyCore
import SwiftUI

@main
struct BaoBuddyApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .onOpenURL { url in
                    model.handleIncomingURL(url)
                }
        }
    }
}
