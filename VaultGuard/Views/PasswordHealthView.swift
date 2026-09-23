import SwiftUI

/// Password health report.
///
/// Opened from the sidebar as a sheet, matching the generator and Sends. Everything here is
/// computed from the vault already in memory — nothing leaves the machine.
struct PasswordHealthView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    private var issues: [PasswordIssue] { PasswordAudit.scan(appState.vaultCiphers) }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if issues.isEmpty {
                VStack(spacing: VGSpacing.m) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(VGFont.emptyGlyph).foregroundColor(.green)
                    Text(L10n.Health.allClear.localized)
                        .font(VGFont.bodyLarge).foregroundColor(VGColor.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                list
            }
        }
        .frame(width: 520, height: 560)
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: VGSpacing.xxs) {
                Text(L10n.Health.title.localized).font(VGFont.title)
                Text(L10n.Health.subtitle.localized)
                    .font(VGFont.caption).foregroundColor(VGColor.secondary)
            }
            Spacer()
            Button(action: { dismiss() }) {
                Image(systemName: "xmark").font(VGFont.bodyEmphasis).foregroundColor(VGColor.secondary)
                    .frame(width: 26, height: 26)
                    .background(VGColor.surface.opacity(0.6)).clipShape(Circle())
            }.buttonStyle(.plain).handCursor().vgHelp(L10n.close.localized)
        }
        .padding(VGSpacing.xxl)
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: VGSpacing.m) {
                ForEach(issues) { issue in
                    Button(action: { reveal(issue) }) {
                        HStack(spacing: VGSpacing.l) {
                            Image(systemName: Self.icon(for: issue.kind))
                                .font(VGFont.body).foregroundColor(Self.tint(for: issue.kind))
                                .frame(width: 20)
                                .vgDecorative()
                            VStack(alignment: .leading, spacing: VGSpacing.xxs) {
                                Text(issue.cipherName).font(VGFont.bodyEmphasis).lineLimit(1)
                                Text(Self.explain(issue.kind))
                                    .font(VGFont.caption).foregroundColor(VGColor.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(VGFont.caption).foregroundColor(VGColor.tertiary).vgDecorative()
                        }
                        .padding(VGSpacing.l)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain).handCursor()
                    .accessibilityElement(children: .combine)
                    // padding: 0 — the row already pads itself, and vgCard's default would
                    // double it.
                    .vgCard(padding: 0)
                }
            }
            .padding(VGSpacing.xxl)
        }
    }

    /// Close the report and put the offending item on screen, so a finding is one click away
    /// from being fixed rather than something to go and look for by hand.
    private func reveal(_ issue: PasswordIssue) {
        appState.filter = .all
        appState.searchText = ""
        appState.selectedCipherIds = [issue.cipherId]
        dismiss()
    }

    private static func icon(for kind: PasswordIssue.Kind) -> String {
        switch kind {
        case .reused: return "doc.on.doc.fill"
        case .weak:   return "exclamationmark.triangle.fill"
        case .empty:  return "questionmark.circle.fill"
        case .stale:  return "clock.fill"
        }
    }

    private static func tint(for kind: PasswordIssue.Kind) -> Color {
        switch kind {
        case .reused, .weak: return .orange
        case .empty, .stale: return VGColor.secondary
        }
    }

    private static func explain(_ kind: PasswordIssue.Kind) -> String {
        switch kind {
        case .reused(let count): return L10n.Health.reused.localized(count)
        case .weak:              return L10n.Health.weak.localized
        case .empty:             return L10n.Health.empty.localized
        case .stale(let days):   return L10n.Health.stale.localized(days)
        }
    }
}
