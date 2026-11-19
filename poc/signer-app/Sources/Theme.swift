import AppKit
import SwiftUI

/// The shared Loki look (docs: loki-design-spec): dark palette, rounded solid cards over the
/// animated vault tunnel. Presentation only; every dialog keeps NSAlert's wording and answers.
enum Loki {
    static let bg = NSColor(srgbRed: 0x0A / 255, green: 0x0C / 255, blue: 0x10 / 255, alpha: 1)
    static let surface = NSColor(srgbRed: 0x12 / 255, green: 0x15 / 255, blue: 0x1C / 255, alpha: 1)
    static let surface2 = NSColor(srgbRed: 0x18 / 255, green: 0x1C / 255, blue: 0x25 / 255, alpha: 1)
    static let border = NSColor(white: 1, alpha: 0.08)
    static let text = NSColor(srgbRed: 0xE8 / 255, green: 0xEA / 255, blue: 0xF0 / 255, alpha: 1)
    static let muted = NSColor(srgbRed: 0x8B / 255, green: 0x93 / 255, blue: 0xA7 / 255, alpha: 1)
    static let accent = NSColor(srgbRed: 0x2F / 255, green: 0xD8 / 255, blue: 0xA8 / 255, alpha: 1)
    static let accentDeep = NSColor(srgbRed: 0x13 / 255, green: 0xA5 / 255, blue: 0x7E / 255, alpha: 1)
    static let gold = NSColor(srgbRed: 0xE8 / 255, green: 0xB4 / 255, blue: 0x4A / 255, alpha: 1)
    static let mono = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)

    /// A solid rounded surface; security-critical text only ever sits on one of these.
    static func box(_ color: NSColor, radius: CGFloat) -> NSView {
        let view = NSView()
        view.wantsLayer = true
        view.layer?.backgroundColor = color.cgColor
        view.layer?.cornerRadius = radius
        view.layer?.borderWidth = 1
        view.layer?.borderColor = border.cgColor
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }

    /// The animated tunnel, filling `root`, with `card` centred on it at `inset` from each edge.
    static func mount(_ card: NSView, in root: NSView, inset: CGFloat) {
        root.wantsLayer = true
        root.layer?.backgroundColor = bg.cgColor
        let tunnel = NSHostingView(rootView: VaultTunnel())
        tunnel.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(tunnel)
        root.addSubview(card)
        NSLayoutConstraint.activate([
            tunnel.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            tunnel.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            tunnel.topAnchor.constraint(equalTo: root.topAnchor),
            tunnel.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            card.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: inset),
            card.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -inset),
            card.topAnchor.constraint(equalTo: root.topAnchor, constant: inset),
            card.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -inset),
        ])
    }

    static func label(_ text: String, font: NSFont, color: NSColor) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: text)
        field.font = font
        field.textColor = color
        return field
    }
}

/// Concentric ellipses receding to a vanishing point, radial lines, rising particles and a soft
/// emerald-to-gold aura. 30 fps; one static frame with Reduce Motion.
struct VaultTunnel: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            TimelineView(.animation(minimumInterval: 1.0 / 30, paused: reduceMotion)) { timeline in
                Canvas { context, size in
                    draw(&context, size, reduceMotion ? 0 : timeline.date.timeIntervalSinceReferenceDate)
                }
            }
            // Scanlines never move, so they are drawn once outside the timeline.
            Canvas { context, size in
                var path = Path()
                for y in stride(from: 0, to: size.height, by: 3) { path.addRect(CGRect(x: 0, y: y, width: size.width, height: 1)) }
                context.fill(path, with: .color(.black.opacity(0.12)))
            }
        }
        .background(Color(Loki.bg))
    }

    private func draw(_ context: inout GraphicsContext, _ size: CGSize, _ t: Double) {
        let line = Color(red: 0x1F / 255, green: 0x24 / 255, blue: 0x30 / 255)
        let center = CGPoint(x: size.width / 2, y: size.height * 0.42)
        let reach = max(size.width, size.height) * 1.1

        // Aura: emerald drifting to gold and back.
        let mix = (sin(t * 0.25) + 1) / 2
        let aura = Color(red: (0x2F + (0xE8 - 0x2F) * mix) / 255, green: (0xD8 + (0xB4 - 0xD8) * mix) / 255,
                         blue: (0xA8 + (0x4A - 0xA8) * mix) / 255)
        var glow = context
        glow.blendMode = .plusLighter
        glow.opacity = 0.5
        let auraRect = CGRect(x: center.x - reach * 0.45, y: center.y - reach * 0.22, width: reach * 0.9, height: reach * 0.44)
        glow.fill(Path(ellipseIn: auraRect), with: .radialGradient(Gradient(colors: [aura.opacity(0.22), .clear]),
            center: center, startRadius: 0, endRadius: reach * 0.4))
        glow.fill(Path(CGRect(origin: .zero, size: size)), with: .linearGradient(
            Gradient(colors: [.clear, Color(Loki.accent).opacity(0.10)]),
            startPoint: CGPoint(x: 0, y: size.height * 0.6), endPoint: CGPoint(x: 0, y: size.height)))

        // Radial lines from the vanishing point.
        var rays = Path()
        for i in 0..<18 {
            let angle = Double(i) / 18 * 2 * .pi
            rays.move(to: center)
            rays.addLine(to: CGPoint(x: center.x + cos(angle) * reach, y: center.y + sin(angle) * reach * 0.6))
        }
        context.stroke(rays, with: .color(line.opacity(0.7)), lineWidth: 1)

        // Discs: each one grows from the vanishing point outward (~0.001 progress per frame at 60 fps).
        let discs = 9
        for i in 0..<discs {
            let p = (Double(i) / Double(discs) + t * 0.06).truncatingRemainder(dividingBy: 1)
            let rx = p * p * reach * 0.8, ry = rx * 0.4
            context.stroke(Path(ellipseIn: CGRect(x: center.x - rx, y: center.y - ry, width: rx * 2, height: ry * 2)),
                with: .color(line.opacity(min(1, p * 3))), lineWidth: 1 + p)
        }

        // Rising particles, placed by a fixed hash of their index.
        for i in 0..<36 {
            let seed = Double(i) * 12.9898
            let r1 = (sin(seed) * 43758.5453).truncatingRemainder(dividingBy: 1).magnitude
            let r2 = (sin(seed * 1.7) * 24634.6345).truncatingRemainder(dividingBy: 1).magnitude
            let rise = (r2 + t * (0.02 + r1 * 0.03)).truncatingRemainder(dividingBy: 1)
            let dot = 1 + r1 * 1.5
            let alpha = (0.2 + 0.7 * r2) * sin(rise * .pi)
            context.fill(Path(ellipseIn: CGRect(x: r1 * size.width, y: size.height * (1 - rise), width: dot, height: dot)),
                with: .color(.white.opacity(alpha)))
        }
    }
}

/// A rounded button with 150 ms hover and press fades. The Return-key button is the filled one,
/// as NSAlert's blue default button is.
final class LokiButton: NSButton {
    private var hovering = false
    private var pressing = false

    init(_ title: String, target: AnyObject?, action: Selector?) {
        super.init(frame: .zero)
        self.title = title
        self.target = target
        self.action = action
        isBordered = false
        wantsLayer = true
        layer?.cornerRadius = 12
        layer?.borderWidth = 1
        font = .systemFont(ofSize: 13, weight: .medium)
        restyle(animated: false)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    override var keyEquivalent: String { didSet { restyle(animated: false) } }
    override var isEnabled: Bool { didSet { restyle(animated: false) } }

    override var intrinsicContentSize: NSSize {
        NSSize(width: super.intrinsicContentSize.width + 32, height: 32)
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: bounds, options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect], owner: self))
    }

    override func mouseEntered(with event: NSEvent) { hovering = true; restyle(animated: true) }
    override func mouseExited(with event: NSEvent) { hovering = false; restyle(animated: true) }

    override func mouseDown(with event: NSEvent) {
        pressing = true
        restyle(animated: true)
        super.mouseDown(with: event) // tracks until mouse-up
        pressing = false
        restyle(animated: true)
    }

    private func restyle(animated: Bool) {
        let primary = keyEquivalent == "\r"
        var fill = primary ? Loki.accent : Loki.surface2
        if pressing { fill = primary ? Loki.accentDeep : Loki.border } else if hovering { fill = fill.blended(withFraction: 0.12, of: .white) ?? fill }
        contentTintColor = primary ? Loki.bg : Loki.text
        alphaValue = isEnabled ? 1 : 0.5
        NSAnimationContext.runAnimationGroup { context in
            context.duration = animated ? 0.15 : 0
            context.timingFunction = CAMediaTimingFunction(name: .easeOut)
            context.allowsImplicitAnimation = animated
            layer?.backgroundColor = fill.cgColor
            layer?.borderColor = (primary ? NSColor.clear : Loki.border).cgColor
        }
    }
}

private final class LokiPanel: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

/// NSAlert's API and answers, drawn in the Loki style. First button = Return, a "Cancel" button =
/// Escape, buttons answer `.alertFirstButtonReturn` onwards, `NSApp.abortModal()` answers `.abort`,
/// and with no buttons added there is one "OK". `detailText` is shown in monospace on its own box.
final class LokiAlert: NSObject {
    var messageText = ""
    var informativeText = ""
    var detailText: String?
    var accessoryView: NSView?
    var alertStyle: NSAlert.Style = .informational
    private(set) var buttons: [LokiButton] = []
    let window: NSWindow = LokiPanel(contentRect: NSRect(x: 0, y: 0, width: 516, height: 200),
        styleMask: [.borderless], backing: .buffered, defer: false)
    private var laidOut = false

    @discardableResult func addButton(withTitle title: String) -> LokiButton {
        let button = LokiButton(title, target: self, action: #selector(answer(_:)))
        button.tag = NSApplication.ModalResponse.alertFirstButtonReturn.rawValue + buttons.count
        button.keyEquivalent = buttons.isEmpty ? "\r" : title == "Cancel" ? "\u{1b}" : ""
        buttons.append(button)
        return button
    }

    @objc private func answer(_ sender: NSButton) {
        NSApp.stopModal(withCode: NSApplication.ModalResponse(rawValue: sender.tag))
    }

    func layout() {
        guard !laidOut else { return }
        laidOut = true
        if buttons.isEmpty { _ = addButton(withTitle: "OK") }
        let width: CGFloat = 420

        let dot = Loki.box(alertStyle == .informational ? Loki.accent : Loki.gold, radius: 4)
        dot.layer?.borderWidth = 0
        dot.widthAnchor.constraint(equalToConstant: 8).isActive = true
        dot.heightAnchor.constraint(equalToConstant: 8).isActive = true
        let title = Loki.label(messageText, font: .systemFont(ofSize: 17, weight: .semibold), color: Loki.text)
        title.preferredMaxLayoutWidth = width - 18
        let heading = NSStackView(views: [dot, title])
        heading.alignment = .centerY
        heading.spacing = 10
        var views: [NSView] = [heading]
        if let detailText {
            let box = Loki.box(Loki.surface2, radius: 12)
            let detail = Loki.label(detailText, font: Loki.mono, color: Loki.text)
            detail.isSelectable = true
            detail.preferredMaxLayoutWidth = width - 24
            detail.translatesAutoresizingMaskIntoConstraints = false
            box.addSubview(detail)
            NSLayoutConstraint.activate([
                detail.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 12),
                detail.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -12),
                detail.topAnchor.constraint(equalTo: box.topAnchor, constant: 12),
                detail.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -12),
                detail.widthAnchor.constraint(equalToConstant: width - 24),
            ])
            views.append(box)
        }
        if !informativeText.isEmpty {
            let info = Loki.label(informativeText, font: .systemFont(ofSize: 13), color: Loki.muted)
            info.preferredMaxLayoutWidth = width
            info.widthAnchor.constraint(equalToConstant: width).isActive = true
            views.append(info)
        }
        if let accessory = accessoryView {
            accessory.translatesAutoresizingMaskIntoConstraints = false
            accessory.widthAnchor.constraint(equalToConstant: accessory.frame.width).isActive = true
            let height = accessory.heightAnchor.constraint(equalToConstant: accessory.frame.height)
            height.priority = .defaultLow
            height.isActive = true
            views.append(accessory)
        }
        // NSAlert puts the first button rightmost.
        buttons.forEach { $0.setContentCompressionResistancePriority(.required, for: .horizontal) }
        let row = NSStackView(views: buttons.reversed())
        row.spacing = 8
        let buttonLine = NSStackView(views: [NSView(), row])
        buttonLine.distribution = .fill
        buttonLine.widthAnchor.constraint(greaterThanOrEqualToConstant: width).isActive = true
        views.append(buttonLine)

        let content = NSStackView(views: views)
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 14
        content.setCustomSpacing(20, after: views[views.count - 2])
        content.translatesAutoresizingMaskIntoConstraints = false
        let card = Loki.box(Loki.surface, radius: 16)
        card.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 24),
            content.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -24),
            content.topAnchor.constraint(equalTo: card.topAnchor, constant: 24),
            content.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -20),
        ])

        let root = NSView()
        root.wantsLayer = true
        root.layer?.cornerRadius = 20
        root.layer?.masksToBounds = true
        Loki.mount(card, in: root, inset: 24)
        window.contentView = root
        window.appearance = NSAppearance(named: .darkAqua)
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = true
        window.isReleasedWhenClosed = false
        window.level = .modalPanel
        window.setContentSize(root.fittingSize)
    }

    @discardableResult func runModal() -> NSApplication.ModalResponse {
        layout()
        window.center()
        window.alphaValue = 0
        window.makeKeyAndOrderFront(nil)
        if let first = window.initialFirstResponder { window.makeFirstResponder(first) }
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.18
            context.timingFunction = CAMediaTimingFunction(name: .easeOut)
            window.animator().alphaValue = 1
        }
        let response = NSApp.runModal(for: window)
        window.orderOut(nil)
        return response
    }
}
