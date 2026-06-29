import SwiftUI

// MARK: - VaultGuard brand mark

struct VaultGuardLogo: View {
    enum Presentation {
        case interface
        case appIcon
    }

    var presentation: Presentation = .interface
    var showsShadow: Bool = true

    static let brandGradient = LinearGradient(
        colors: [
            Color(red: 0.26, green: 0.53, blue: 0.98),
            Color(red: 0.74, green: 0.26, blue: 0.87),
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    var body: some View {
        GeometryReader { proxy in
            let side = min(proxy.size.width, proxy.size.height)

            ZStack {
                background(side: side)

                ShieldShape()
                    .fill(.white)
                    .shadow(
                        color: showsShadow
                            ? .black.opacity(0.18)
                            : .clear,
                        radius: side * 0.03,
                        x: 0,
                        y: side * 0.02
                    )
                    .frame(
                        width: side * 0.46875,
                        height: side * 0.6015625
                    )

                PadlockShape()
                    .fill(Self.brandGradient)
                    .frame(
                        width: side * 0.234375,
                        height: side * 0.3359375
                    )
                    .offset(y: -side * 0.0234375)
            }
            .frame(width: side, height: side)
            .position(
                x: proxy.size.width / 2,
                y: proxy.size.height / 2
            )
            .compositingGroup()
        }
        .aspectRatio(1, contentMode: .fit)
        .accessibilityHidden(true)
    }

    @ViewBuilder
    private func background(side: CGFloat) -> some View {
        switch presentation {
        case .interface:
            RoundedRectangle(
                cornerRadius: side * 0.225,
                style: .continuous
            )
            .fill(Self.brandGradient)

        case .appIcon:
            Rectangle()
                .fill(Self.brandGradient)
        }
    }
}

// MARK: - Shield

private struct ShieldShape: Shape {
    func path(in rect: CGRect) -> Path {
        let w = rect.width
        let h = rect.height
        var p = Path()

        p.move(to: CGPoint(x: w * 0.50, y: 0))

        p.addLine(
            to: CGPoint(
                x: w * 0.93,
                y: h * 0.125
            )
        )

        p.addCurve(
            to: CGPoint(
                x: w,
                y: h * 0.205
            ),
            control1: CGPoint(
                x: w * 0.97,
                y: h * 0.135
            ),
            control2: CGPoint(
                x: w,
                y: h * 0.165
            )
        )

        p.addLine(
            to: CGPoint(
                x: w,
                y: h * 0.595
            )
        )

        p.addCurve(
            to: CGPoint(
                x: w * 0.50,
                y: h
            ),
            control1: CGPoint(
                x: w,
                y: h * 0.755
            ),
            control2: CGPoint(
                x: w * 0.84,
                y: h * 0.86
            )
        )

        p.addCurve(
            to: CGPoint(
                x: 0,
                y: h * 0.595
            ),
            control1: CGPoint(
                x: w * 0.16,
                y: h * 0.86
            ),
            control2: CGPoint(
                x: 0,
                y: h * 0.755
            )
        )

        p.addLine(
            to: CGPoint(
                x: 0,
                y: h * 0.205
            )
        )

        p.addCurve(
            to: CGPoint(
                x: w * 0.07,
                y: h * 0.125
            ),
            control1: CGPoint(
                x: 0,
                y: h * 0.165
            ),
            control2: CGPoint(
                x: w * 0.03,
                y: h * 0.135
            )
        )

        p.addLine(
            to: CGPoint(
                x: w * 0.50,
                y: 0
            )
        )

        p.closeSubpath()
        return p
    }
}

// MARK: - Padlock

private struct PadlockShape: Shape {
    func path(in rect: CGRect) -> Path {
        let w = rect.width
        let h = rect.height
        var p = Path()

        let bodyTop = h * (17.0 / 43.0)
        let bodyCorner = w * (3.0 / 30.0)

        p.addRoundedRect(
            in: CGRect(
                x: 0,
                y: bodyTop,
                width: w,
                height: h - bodyTop
            ),
            cornerSize: CGSize(
                width: bodyCorner,
                height: bodyCorner
            ),
            style: .circular
        )

        let outerRadius = w * 0.39
        let shackleWidth = w * 0.155
        let centerlineRadius =
            outerRadius - shackleWidth / 2
        let centerY = outerRadius

        let leftLegX =
            w * 0.5 - outerRadius

        let rightLegX =
            w * 0.5 + outerRadius - shackleWidth

        let legHeight =
            bodyTop - centerY

        p.addRect(
            CGRect(
                x: leftLegX,
                y: centerY,
                width: shackleWidth,
                height: legHeight
            )
        )

        p.addRect(
            CGRect(
                x: rightLegX,
                y: centerY,
                width: shackleWidth,
                height: legHeight
            )
        )

        let arc = Path { arc in
            arc.addArc(
                center: CGPoint(
                    x: w * 0.5,
                    y: centerY
                ),
                radius: centerlineRadius,
                startAngle: .degrees(180),
                endAngle: .degrees(0),
                clockwise: false
            )
        }

        p.addPath(
            arc.strokedPath(
                StrokeStyle(
                    lineWidth: shackleWidth,
                    lineCap: .butt,
                    lineJoin: .miter
                )
            )
        )

        return p
    }
}
