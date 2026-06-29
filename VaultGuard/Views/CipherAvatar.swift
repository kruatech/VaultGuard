import SwiftUI

/// Reusable item avatar: a KeePass entry icon when present, otherwise a colour-gradient
/// tile with the cipher's initials. Shared by the items list (size 34) and the detail
/// header (size 44). The per-item gradient is decorative / data-driven and intentionally
/// not tokenised (see VGDesign).
struct CipherAvatar: View {
    let cipher: VaultCipher
    var size: CGFloat = 34
    var glyph: CGFloat = 16
    var corner: CGFloat = VGRadius.medium
    var initialsFont: Font = VGFont.bodyBold

    var body: some View {
        if let kpIcon = cipher.keepassIcon {
            KeePassIconImage(ref: kpIcon, size: size, glyph: glyph, corner: corner)
        } else {
            RoundedRectangle(cornerRadius: corner).fill(accentGradient).frame(width: size, height: size)
                .overlay { Text(cipher.initials).font(initialsFont).foregroundColor(VGColor.onAccent) }
        }
    }

    private var accentGradient: LinearGradient {
        let c: [Color] = { switch cipher.accentColorName {
        case "blue": return [.blue, .cyan]; case "green": return [.green, .mint]
        case "orange": return [.orange, .yellow]; case "purple": return [.purple, .pink]
        case "red": return [.red, .orange]; default: return [.blue, .cyan]
        } }()
        return LinearGradient(colors: c, startPoint: .topLeading, endPoint: .bottomTrailing)
    }
}
