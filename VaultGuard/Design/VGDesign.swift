import SwiftUI
import AppKit

// MARK: - VaultGuard Design Tokens
//
// A single source of truth for typography, colour, spacing and corner radii.
//
// This file is intentionally ADDITIVE: nothing in the app uses it yet. Screens are
// migrated onto these tokens one at a time (with a build after each) so that any
// visual change is reviewable in isolation. The values below were chosen to match
// the sizes/colours already in use, so the first migration of a screen should be a
// visual no-op — only the call sites change (e.g. `.font(.system(size: 12, weight:
// .semibold))` becomes `.font(VGFont.labelEmphasis)`).
//
// Usage:
//   Text("Title").font(VGFont.title)
//   someView.foregroundColor(VGColor.secondary)
//   VStack(spacing: VGSpacing.m) { ... }
//   card.vgCard()                       // standard settings/detail card surface

// MARK: - Accessibility

extension View {
    /// Tooltip *and* VoiceOver label from one string.
    ///
    /// `.help(_:)` alone gives a hover tooltip and an accessibility *hint*, but an icon-only
    /// button still has no accessibility *label* — VoiceOver falls back to announcing the SF
    /// Symbol name, or nothing at all. Every icon button in the app already passes a localized
    /// string to `.help`, so this pairs the two rather than inventing a second set of strings
    /// that could drift apart.
    func vgHelp(_ text: String) -> some View {
        self.help(text).accessibilityLabel(Text(text))
    }

    /// Marks a purely decorative glyph so VoiceOver skips it instead of reading an SF Symbol
    /// name. Use only where an adjacent label already carries the meaning.
    func vgDecorative() -> some View {
        self.accessibilityHidden(true)
    }
}

// MARK: - Spacing

enum VGSpacing {
    static let xxs: CGFloat = 2
    static let xs:  CGFloat = 4
    static let s:   CGFloat = 6
    static let m:   CGFloat = 8
    static let l:   CGFloat = 10
    static let xl:  CGFloat = 14
    static let xxl: CGFloat = 16
    static let xxxl: CGFloat = 20
    static let huge: CGFloat = 24
}

// MARK: - Corner radii

enum VGRadius {
    static let small:  CGFloat = 6
    static let medium: CGFloat = 8
    static let large:  CGFloat = 10
}

// MARK: - Typography
//
// Semantic roles mapped to the system font. Names describe purpose, not size, so a
// future global type-scale change happens here rather than across every view.

enum VGFont {
    /// Multiplier applied to every size below. Owned by `TextScaleManager`, which persists it
    /// and pushes changes here; kept as a plain static so the roles stay usable from anywhere
    /// without threading an environment object through every view.
    ///
    /// Every role is a computed `var` rather than a stored `let` for this reason: a `let`
    /// would capture the size once at first use and never follow the setting.
    static var scale: CGFloat = 1

    private static func scaled(_ size: CGFloat, weight: Font.Weight = .regular,
                               design: Font.Design = .default) -> Font {
        // Round to whole points: the system font hints better on integers, and half-point
        // sizes made the monospaced columns shimmer as the scale changed.
        Font.system(size: (size * scale).rounded(), weight: weight, design: design)
    }

    // Titles
    static var largeTitle: Font { scaled(18, weight: .bold) }      // screen titles
    static var title: Font { scaled(17, weight: .bold) }      // window / sheet headers
    static var title2: Font { scaled(16, weight: .semibold) }
    static var title2Bold: Font { scaled(16, weight: .bold) }
    static var title3: Font { scaled(15, weight: .semibold) }
    static var title3Bold: Font { scaled(15, weight: .bold) }
    static var subheadline: Font { scaled(15) }

    // Body (13pt baseline)
    static var headline: Font { scaled(14, weight: .semibold) }
    static var headlineMedium: Font { scaled(14, weight: .medium) }
    static var bodyLarge: Font { scaled(14) }
    static var body: Font { scaled(13) }
    static var bodyEmphasis: Font { scaled(13, weight: .semibold) }
    static var bodyMedium: Font { scaled(13, weight: .medium) }
    static var bodyBold: Font { scaled(13, weight: .bold) }
    static var bodyMono: Font { scaled(13, design: .monospaced) }
    static var bodyMonoBold: Font { scaled(13, weight: .bold, design: .monospaced) }

    // Labels / controls (12pt — the workhorse size)
    static var label: Font { scaled(12) }
    static var labelEmphasis: Font { scaled(12, weight: .semibold) }
    static var labelMedium: Font { scaled(12, weight: .medium) }
    static var labelBold: Font { scaled(12, weight: .bold) }
    static var labelMono: Font { scaled(12, design: .monospaced) }

    // Captions
    static var caption: Font { scaled(11) }
    static var captionEmphasis: Font { scaled(11, weight: .semibold) }
    static var captionMedium: Font { scaled(11, weight: .medium) }
    static var captionBold: Font { scaled(11, weight: .bold) }
    static var captionMono: Font { scaled(11, design: .monospaced) }
    static var caption2: Font { scaled(10) }
    static var caption2Emphasis: Font { scaled(10, weight: .semibold) }
    static var badge: Font { scaled(9, weight: .semibold) }

    // Special-purpose
    static var codeDisplay: Font { scaled(24, weight: .semibold, design: .monospaced) } // TOTP code
    static var passwordMono: Font { scaled(14, weight: .medium, design: .monospaced) } // generated password readout
    static var emptyGlyph: Font { scaled(36, weight: .ultraLight) }                     // empty-state icon
    static var emptyGlyphLarge: Font { scaled(48, weight: .ultraLight) }                 // larger empty/placeholder glyph
    static var brandTitle: Font { scaled(28, weight: .bold, design: .rounded) }          // auth app title
    static var brandIcon: Font { scaled(40) }                                          // auth logo icon
    static var brandIconLarge: Font { scaled(48, weight: .light) }                       // auth logo, large
    static var iconLarge: Font { scaled(22) }                                          // SF Symbol, large
    static var glyphLight: Font { scaled(24, weight: .light) }                          // SF Symbol, light
}

// MARK: - Colour
//
// System/semantic colours so the app adapts to light/dark/high-contrast and
// accessibility settings. Decorative per-item avatar gradients are data-driven and
// intentionally not tokenised here.

enum VGColor {
    // Text
    static let primary    = Color.primary
    static let secondary  = Color.secondary
    static let tertiary   = Color(NSColor.tertiaryLabelColor)
    static let quaternary = Color(NSColor.quaternaryLabelColor)

    // Surfaces
    static let surface   = Color(NSColor.controlBackgroundColor)   // cards, controls
    static let field     = Color(NSColor.textBackgroundColor)      // editable fields
    static let window    = Color(NSColor.windowBackgroundColor)
    static let separator = Color(NSColor.separatorColor)

    // Accent & status
    static let accent   = Color.accentColor
    static let success  = Color.green
    static let warning  = Color.orange
    static let danger   = Color.red
    static let onAccent = Color.white
}

// MARK: - Surfaces

extension View {
    /// Standard VaultGuard card: padded surface with a large radius and a hairline border.
    /// Mirrors the look currently produced inline by `SettingsView.settingsSection` and the
    /// detail-screen cards, so those can be migrated to this without a visual change.
    func vgCard(padding: CGFloat = VGSpacing.xl) -> some View {
        self
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(VGColor.surface)
            .cornerRadius(VGRadius.large)
            .overlay(
                RoundedRectangle(cornerRadius: VGRadius.large)
                    .stroke(VGColor.secondary.opacity(0.1), lineWidth: 0.5)
            )
    }

    /// Compact field surface used by detail rows (e.g. a value with a copy button):
    /// padded, filled with the control background, medium radius.
    func vgFieldSurface(padding: CGFloat = VGSpacing.l, radius: CGFloat = VGRadius.medium) -> some View {
        self
            .padding(padding)
            .background(VGColor.surface)
            .cornerRadius(radius)
    }
}
