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
    // Titles
    static let largeTitle = Font.system(size: 18, weight: .bold)      // screen titles
    static let title      = Font.system(size: 17, weight: .bold)      // window / sheet headers
    static let title2     = Font.system(size: 16, weight: .semibold)
    static let title2Bold = Font.system(size: 16, weight: .bold)
    static let title3     = Font.system(size: 15, weight: .semibold)
    static let title3Bold = Font.system(size: 15, weight: .bold)
    static let subheadline = Font.system(size: 15)

    // Body (13pt baseline)
    static let headline     = Font.system(size: 14, weight: .semibold)
    static let headlineMedium = Font.system(size: 14, weight: .medium)
    static let bodyLarge     = Font.system(size: 14)
    static let body         = Font.system(size: 13)
    static let bodyEmphasis = Font.system(size: 13, weight: .semibold)
    static let bodyMedium   = Font.system(size: 13, weight: .medium)
    static let bodyBold     = Font.system(size: 13, weight: .bold)
    static let bodyMono     = Font.system(size: 13, design: .monospaced)
    static let bodyMonoBold = Font.system(size: 13, weight: .bold, design: .monospaced)

    // Labels / controls (12pt — the workhorse size)
    static let label         = Font.system(size: 12)
    static let labelEmphasis = Font.system(size: 12, weight: .semibold)
    static let labelMedium   = Font.system(size: 12, weight: .medium)
    static let labelBold     = Font.system(size: 12, weight: .bold)
    static let labelMono     = Font.system(size: 12, design: .monospaced)

    // Captions
    static let caption          = Font.system(size: 11)
    static let captionEmphasis  = Font.system(size: 11, weight: .semibold)
    static let captionMedium    = Font.system(size: 11, weight: .medium)
    static let captionBold      = Font.system(size: 11, weight: .bold)
    static let captionMono      = Font.system(size: 11, design: .monospaced)
    static let caption2         = Font.system(size: 10)
    static let caption2Emphasis = Font.system(size: 10, weight: .semibold)
    static let badge            = Font.system(size: 9, weight: .semibold)

    // Special-purpose
    static let codeDisplay = Font.system(size: 24, weight: .semibold, design: .monospaced) // TOTP code
    static let passwordMono = Font.system(size: 14, weight: .medium, design: .monospaced) // generated password readout
    static let emptyGlyph  = Font.system(size: 36, weight: .ultraLight)                     // empty-state icon
    static let emptyGlyphLarge = Font.system(size: 48, weight: .ultraLight)                 // larger empty/placeholder glyph
    static let brandTitle  = Font.system(size: 28, weight: .bold, design: .rounded)          // auth app title
    static let brandIcon   = Font.system(size: 40)                                          // auth logo icon
    static let brandIconLarge = Font.system(size: 48, weight: .light)                       // auth logo, large
    static let iconLarge   = Font.system(size: 22)                                          // SF Symbol, large
    static let glyphLight  = Font.system(size: 24, weight: .light)                          // SF Symbol, light
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
