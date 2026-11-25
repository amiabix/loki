import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  private var walletChannel: WalletChannel?

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    walletChannel = WalletChannel(messenger: flutterViewController.engine.binaryMessenger, window: self)
    styleMask.insert(.fullSizeContentView)
    titlebarAppearsTransparent = true
    titleVisibility = .hidden
    title = "Loki"
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
    for name in [NSWindow.didResizeNotification, NSWindow.didExitFullScreenNotification, NSWindow.didBecomeKeyNotification] {
      NotificationCenter.default.addObserver(forName: name, object: self, queue: .main) { [weak self] _ in self?.placeWindowButtons() }
    }
    placeWindowButtons()
  }

  /// Floating sidebar inset from the window edge; main.dart uses the same values.
  static var sidebarInset: CGFloat {
    if #available(macOS 26, *) { return 8 }
    return 4
  }

  /// Puts the traffic lights inside the floating sidebar, 12 pt from its top and left edges.
  private func placeWindowButtons() {
    guard !styleMask.contains(.fullScreen), let close = standardWindowButton(.closeButton),
          let container = close.superview?.superview else { return }
    let edge = Self.sidebarInset + 12
    var bar = container.frame
    bar.size.height = edge + close.frame.height
    bar.origin.y = frame.height - bar.height
    container.frame = bar
    let dx = edge - close.frame.minX
    for kind in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] {
      guard let button = standardWindowButton(kind) else { continue }
      button.setFrameOrigin(NSPoint(x: button.frame.minX + dx, y: 0))
    }
  }
}

@available(macOS 26, *)
private final class GlassSidebarFactory: NSObject, FlutterPlatformViewFactory {
  func create(withViewIdentifier viewId: Int64, arguments args: Any?) -> NSView {
    let view = GlassSidebar()
    view.cornerRadius = 9  // window corner (~17 pt, measured on macOS 27) minus the 8 pt inset
    view.contentView = NSView()
    return view
  }
}

@available(macOS 26, *)
private final class GlassSidebar: NSGlassEffectView {
  override func hitTest(_ point: NSPoint) -> NSView? { nil }
}
