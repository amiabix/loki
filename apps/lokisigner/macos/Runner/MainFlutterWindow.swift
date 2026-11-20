import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private var walletChannel: WalletChannel?

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    walletChannel = WalletChannel(messenger: flutterViewController.engine.binaryMessenger)
    styleMask.insert(.fullSizeContentView)
    titlebarAppearsTransparent = true
    titleVisibility = .hidden
    title = "LokiSigner"
    minSize = NSSize(width: 880, height: 560)
    contentViewController = flutterViewController
    setFrame(NSRect(origin: frame.origin, size: NSSize(width: 1040, height: 644)), display: true)
    center()

    if #available(macOS 26, *) {
      flutterViewController.registrar(forPlugin: "LokiSidebarGlass")
        .register(GlassSidebarFactory(), withId: "cash.loki/sidebar-glass")
    }
    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }
}

@available(macOS 26, *)
private final class GlassSidebarFactory: NSObject, FlutterPlatformViewFactory {
  func create(withViewIdentifier viewId: Int64, arguments args: Any?) -> NSView {
    let view = GlassSidebar()
    view.cornerRadius = 17
    view.contentView = NSView()
    return view
  }
}

@available(macOS 26, *)
private final class GlassSidebar: NSGlassEffectView {
  override func hitTest(_ point: NSPoint) -> NSView? { nil }
}
