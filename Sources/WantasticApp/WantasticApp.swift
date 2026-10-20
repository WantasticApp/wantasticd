import AppKit
import SwiftUI
import WantasticCore
#if !WANTASTIC_XCODE_APP
import WantasticTunnel
#endif

enum WantasticAssets {
    private static var nativeLogo: NSImage? {
        #if WANTASTIC_XCODE_APP
        if let image = NSImage(named: NSImage.Name("WantasticLogo")) { return image }
        guard let url = Bundle.main.url(forResource: "WantasticLogoSwiftPM", withExtension: "png") else {
            return nil
        }
        return NSImage(contentsOf: url)
        #else
        guard let url = Bundle.module.url(forResource: "WantasticLogoSwiftPM", withExtension: "png") else {
            return nil
        }
        return NSImage(contentsOf: url)
        #endif
    }

    static var logo: Image {
        #if WANTASTIC_XCODE_APP
        Image("WantasticLogo", bundle: .main)
        #else
        if let url = Bundle.module.url(forResource: "WantasticLogoSwiftPM", withExtension: "png"),
           let image = NSImage(contentsOf: url) {
            Image(nsImage: image)
        } else {
            Image(systemName: "network")
        }
        #endif
    }

    static func menuBarGlyph(for state: ConnectionState) -> NSImage {
        let image = NSImage(size: NSSize(width: 20, height: 20))
        image.lockFocus()
        if let logo = nativeLogo {
            logo.draw(in: NSRect(x: 0, y: 1, width: 17, height: 17),
                      from: NSRect(origin: .zero, size: logo.size), operation: .sourceOver, fraction: 1)
        }
        (state == .connected ? NSColor.systemGreen : NSColor.systemRed).setFill()
        NSBezierPath(ovalIn: NSRect(x: 14, y: 1, width: 6, height: 6)).fill()
        image.unlockFocus()
        image.isTemplate = false
        return image
    }
}

enum ConnectionStatusStyle {
    static func color(for state: ConnectionState) -> Color {
        switch state {
        case .connected: .green
        case .connecting, .needsApproval: .orange
        case .disconnected: .secondary
        case .failed: .red
        }
    }
}

struct ConnectionBrandMark: View {
    let state: ConnectionState

    var body: some View {
        WantasticAssets.logo
            .resizable()
            .scaledToFit()
            .overlay(alignment: .bottomTrailing) {
                Circle()
                    .fill(state == .connected ? Color.green : Color.red)
                    .frame(width: 7, height: 7)
                    .overlay(Circle().stroke(.background, lineWidth: 1.5))
            }
            .accessibilityHidden(true)
    }
}

@main
struct WantasticApp: App {
    @StateObject private var tunnelController = TunnelController()
    @AppStorage("language") private var language = AppLanguage.english.rawValue

    var body: some Scene {
        MenuBarExtra {
            MenuBarPanel().environmentObject(tunnelController)
        } label: {
            Image(nsImage: WantasticAssets.menuBarGlyph(for: tunnelController.state))
                .resizable()
                .scaledToFit()
                .frame(width: 20, height: 20)
                .accessibilityLabel(Text(
                    "Wantastic " + AppCopy.text(
                        tunnelController.state.trayStatusCopyKey,
                        language: AppLanguage(rawValue: language) ?? .english)
                ))
        }
        .menuBarExtraStyle(.window)
    }
}
