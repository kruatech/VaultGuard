import SwiftUI
import AppKit

/// A thin wrapper over `NSTextField` that fixes the shortcomings of SwiftUI's
/// `TextField(.plain)` on macOS: text is vertically centered inside the field,
/// the field never grows/shrinks with its content (single line), and long text
/// is clipped at the trailing edge instead of overflowing the frame.
///
/// Border/background are intentionally NOT drawn here — the caller wraps it in
/// its own container (`fieldBox`). Set `isSecure` to mask input (password).
struct VGTextField: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String = ""
    var isSecure: Bool = false
    var monospaced: Bool = false

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSTextField {
        makeField(secure: isSecure, context: context)
    }

    func updateNSView(_ nsView: NSTextField, context: Context) {
        // Keep value in sync.
        if nsView.stringValue != text { nsView.stringValue = text }
        nsView.placeholderString = placeholder
        applyFont(to: nsView)

        // If the secure-ness changed, the underlying NSView class must change too.
        let isCurrentlySecure = nsView is NSSecureTextField
        if isCurrentlySecure != isSecure {
            // Ask the parent representable to rebuild by swapping the view.
            let newField = makeField(secure: isSecure, context: context)
            newField.stringValue = text
            if let superview = nsView.superview {
                superview.addSubview(newField)
                newField.frame = nsView.frame
                nsView.removeFromSuperview()
            }
        }
    }

    private func makeField(secure: Bool, context: Context) -> NSTextField {
        let field: NSTextField = secure
            ? VGSecureTextField()
            : VGPlainTextField()
        field.delegate = context.coordinator
        field.isBordered = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.lineBreakMode = .byClipping
        field.usesSingleLineMode = true
        field.cell?.usesSingleLineMode = true
        field.cell?.isScrollable = true
        field.cell?.wraps = false
        field.stringValue = text
        field.placeholderString = placeholder
        field.translatesAutoresizingMaskIntoConstraints = false
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        applyFont(to: field)
        return field
    }

    private func applyFont(to field: NSTextField) {
        let size: CGFloat = 13
        field.font = monospaced
            ? NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
            : NSFont.systemFont(ofSize: size)
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        private let parent: VGTextField
        init(_ parent: VGTextField) { self.parent = parent }
        func controlTextDidChange(_ obj: Notification) {
            guard let field = obj.object as? NSTextField else { return }
            parent.text = field.stringValue
        }
    }
}

// MARK: - Vertically-centering cell

/// Cell that centers its text vertically within the field's bounds. NSTextField
/// otherwise top-aligns text, which makes a fixed-height field look off.
private final class VGCenteredCell: NSTextFieldCell {
    private func centered(_ rect: NSRect) -> NSRect {
        let textHeight = (stringValue as NSString).size(withAttributes: [.font: font ?? NSFont.systemFont(ofSize: 13)]).height
        guard textHeight < rect.height else { return rect }
        let y = rect.origin.y + (rect.height - textHeight) / 2
        return NSRect(x: rect.origin.x, y: y, width: rect.width, height: textHeight)
    }
    override func drawingRect(forBounds rect: NSRect) -> NSRect {
        super.drawingRect(forBounds: centered(rect))
    }
    override func edit(withFrame rect: NSRect, in controlView: NSView, editor textObj: NSText, delegate: Any?, event: NSEvent?) {
        super.edit(withFrame: centered(rect), in: controlView, editor: textObj, delegate: delegate, event: event)
    }
    override func select(withFrame rect: NSRect, in controlView: NSView, editor textObj: NSText, delegate: Any?, start: Int, length: Int) {
        super.select(withFrame: centered(rect), in: controlView, editor: textObj, delegate: delegate, start: start, length: length)
    }
}

private final class VGSecureCell: NSSecureTextFieldCell {
    private func centered(_ rect: NSRect) -> NSRect {
        let textHeight = (stringValue as NSString).size(withAttributes: [.font: font ?? NSFont.systemFont(ofSize: 13)]).height
        guard textHeight < rect.height else { return rect }
        let y = rect.origin.y + (rect.height - textHeight) / 2
        return NSRect(x: rect.origin.x, y: y, width: rect.width, height: textHeight)
    }
    override func drawingRect(forBounds rect: NSRect) -> NSRect {
        super.drawingRect(forBounds: centered(rect))
    }
    override func edit(withFrame rect: NSRect, in controlView: NSView, editor textObj: NSText, delegate: Any?, event: NSEvent?) {
        super.edit(withFrame: centered(rect), in: controlView, editor: textObj, delegate: delegate, event: event)
    }
    override func select(withFrame rect: NSRect, in controlView: NSView, editor textObj: NSText, delegate: Any?, start: Int, length: Int) {
        super.select(withFrame: centered(rect), in: controlView, editor: textObj, delegate: delegate, start: start, length: length)
    }
}

private final class VGPlainTextField: NSTextField {
    override class var cellClass: AnyClass? { get { VGCenteredCell.self } set {} }
}

private final class VGSecureTextField: NSSecureTextField {
    override class var cellClass: AnyClass? { get { VGSecureCell.self } set {} }
}
