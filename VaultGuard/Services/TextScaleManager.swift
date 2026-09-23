import Foundation
import SwiftUI
import Combine

/// In-app text scale.
///
/// macOS has no Dynamic Type. Apple's developer support states plainly that Dynamic Type is a
/// system-level feature of iOS, iPadOS, tvOS, visionOS and watchOS; on macOS
/// `NSFont.preferredFont(forTextStyle:)` ignores the Accessibility text-size setting, and
/// SwiftUI's own fonts measure identically from `xSmall` through `accessibility5`. Moving
/// `VGFont` onto `.body` / `.callout` / `.footnote` would shift every size in the app and buy
/// nothing for a low-vision user.
///
/// So the app carries its own scale instead, the way other Mac apps do it. One stored factor,
/// applied inside `VGFont`, driven from ⌘+ / ⌘− / ⌘0 and a slider in Settings.
@MainActor
final class TextScaleManager: ObservableObject {
    static let shared = TextScaleManager()

    /// Below 1 the app is only ever made denser, which nobody needs an accessibility control
    /// for; above 1.5 the sidebar labels and the two-pane split stop fitting. The window is
    /// what the layout can actually absorb, not a judgement about how large text should be.
    static let minimum: CGFloat = 0.85
    static let maximum: CGFloat = 1.5
    static let step: CGFloat = 0.05

    private static let key = "textScale"

    @Published var scale: CGFloat {
        didSet {
            // Assigning inside a property's own `didSet` does not re-enter it, so the
            // correction below is applied once and the persistence and the push must use
            // `clamped` rather than re-reading `scale`.
            let clamped = Self.clamp(scale)
            if clamped != scale { scale = clamped }
            UserDefaults.standard.set(Double(clamped), forKey: Self.key)
            VGFont.scale = clamped
        }
    }

    private init() {
        let stored = UserDefaults.standard.object(forKey: Self.key) as? Double
        // `CGFloat.init` as a function value is ambiguous — it has an overload for every
        // numeric type. The closure pins it to the Double one.
        let initial = Self.clamp(stored.map { CGFloat($0) } ?? 1)
        scale = initial
        VGFont.scale = initial
    }

    var canIncrease: Bool { scale < Self.maximum }
    var canDecrease: Bool { scale > Self.minimum }

    func increase() { scale = Self.clamp(scale + Self.step) }
    func decrease() { scale = Self.clamp(scale - Self.step) }
    func reset() { scale = 1 }

    /// Shown next to the control: "100%", "115%".
    var percentLabel: String { "\(Int((scale * 100).rounded()))%" }

    private static func clamp(_ v: CGFloat) -> CGFloat {
        guard v.isFinite else { return 1 }
        return min(max(v, minimum), maximum)
    }
}
