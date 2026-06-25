import SwiftUI
import AppKit

extension View {
    /// Show the pointing-hand cursor while hovering (macOS).
    func handCursor() -> some View {
        onHover { inside in
            if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
        }
    }
}
