# VaultGuard Design System

VaultGuard's UI uses a small set of design tokens defined in
[`VaultGuard/Design/VGDesign.swift`](../VaultGuard/Design/VGDesign.swift). They
are the single source of truth for typography, colour, spacing and corner radii,
so a change to the type scale or palette happens in one file rather than across
every view.

All screens have been migrated onto these tokens. New UI should use them rather
than raw `.font(.system(size:))` / `Color(NSColor.…)` literals.

## Typography — `VGFont`

Semantic roles mapped to the system font (names describe purpose, not size):

- Titles: `largeTitle` (18 bold), `title` (17 bold), `title2` (16 semibold),
  `title2Bold`, `title3` (15 semibold), `title3Bold`, `subheadline` (15).
- Body (13pt baseline): `body`, `bodyEmphasis`, `bodyMedium`, `bodyBold`,
  `bodyLarge` (14), `bodyMono`, `bodyMonoBold`.
- Headline: `headline` (14 semibold), `headlineMedium`.
- Labels (12pt — the workhorse): `label`, `labelEmphasis`, `labelMedium`,
  `labelBold`, `labelMono`.
- Captions: `caption` (11), `captionEmphasis`, `captionMedium`, `captionBold`,
  `captionMono`, `caption2` (10), `caption2Emphasis`, `badge` (9 semibold).
- Special: `codeDisplay` (24 mono — TOTP), `passwordMono` (generated password),
  `emptyGlyph` (36) / `emptyGlyphLarge` (48) — empty-state icons,
  `iconLarge` (22), `glyphLight` (24 light), and the auth-screen brand set
  `brandTitle` / `brandIcon` / `brandIconLarge`.

```swift
Text("Server").font(VGFont.labelEmphasis)
```

## Colour — `VGColor`

System/semantic colours so the app adapts to light/dark/high-contrast:

- Text: `primary`, `secondary`, `tertiary`, `quaternary`.
- Surfaces: `surface` (cards/controls), `field` (editable fields), `window`,
  `separator`.
- Accent & status: `accent`, `success`, `warning`, `danger`, `onAccent`.

```swift
someView.foregroundColor(VGColor.secondary)
```

Decorative, data-driven colours (per-item avatar gradients, the favourite star)
are intentionally **not** tokenised — they are brand decoration, not semantic UI
colour.

## Spacing & radii — `VGSpacing`, `VGRadius`

- `VGSpacing`: `xxs` 2, `xs` 4, `s` 6, `m` 8, `l` 10, `xl` 14, `xxl` 16,
  `xxxl` 20, `huge` 24.
- `VGRadius`: `small` 6, `medium` 8, `large` 10.

A few one-off radii (2, 4, 7, 12) remain as literals where normalising them to a
token would change the visuals; normalise deliberately if desired.

## Surfaces

Two `View` modifiers package the recurring card looks:

- `.vgCard(padding:)` — padded surface, large radius, hairline border. Used by
  the settings sections and detail cards.
- `.vgFieldSurface(padding:radius:)` — compact filled surface for value rows.

```swift
VStack { … }.vgCard()
```

## Adding tokens

If a new screen needs a size/weight/colour that has no token, add it to
`VGDesign.swift` with a role-based name rather than inlining a literal. Because
`VGDesign.swift` already exists in the target, editing it does not require
`xcodegen generate`; only adding a brand-new source file does.
