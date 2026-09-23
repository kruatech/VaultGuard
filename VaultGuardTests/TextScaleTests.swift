import XCTest
import SwiftUI

/// The text scale is the app's stand-in for Dynamic Type, which macOS does not have. The
/// clamping is what these assert: a factor outside the window the layout can absorb does not
/// make the app more readable, it makes the sidebar unusable.
final class TextScaleTests: XCTestCase {

    private var original: CGFloat = 1

    @MainActor
    override func setUp() {
        super.setUp()
        original = TextScaleManager.shared.scale
    }

    @MainActor
    override func tearDown() {
        TextScaleManager.shared.scale = original
        super.tearDown()
    }

    // MARK: Bounds

    @MainActor func testScaleIsClampedToTheUpperBound() {
        TextScaleManager.shared.scale = 99
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.maximum)
    }

    @MainActor func testScaleIsClampedToTheLowerBound() {
        TextScaleManager.shared.scale = 0.1
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.minimum)
    }

    /// A zero or negative factor would collapse every font to nothing.
    @MainActor func testNonPositiveScaleIsClamped() {
        TextScaleManager.shared.scale = 0
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.minimum)
        TextScaleManager.shared.scale = -5
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.minimum)
    }

    /// NaN reaching a font size is a crash, not a layout problem.
    @MainActor func testNonFiniteScaleFallsBackToOne() {
        TextScaleManager.shared.scale = .nan
        XCTAssertEqual(TextScaleManager.shared.scale, 1)
        TextScaleManager.shared.scale = .infinity
        XCTAssertEqual(TextScaleManager.shared.scale, 1)
    }

    // MARK: Stepping

    @MainActor func testIncreaseStopsAtTheMaximum() {
        TextScaleManager.shared.scale = TextScaleManager.maximum
        TextScaleManager.shared.increase()
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.maximum)
        XCTAssertFalse(TextScaleManager.shared.canIncrease)
    }

    @MainActor func testDecreaseStopsAtTheMinimum() {
        TextScaleManager.shared.scale = TextScaleManager.minimum
        TextScaleManager.shared.decrease()
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.minimum)
        XCTAssertFalse(TextScaleManager.shared.canDecrease)
    }

    @MainActor func testStepChangesByExactlyOneStep() {
        TextScaleManager.shared.scale = 1
        TextScaleManager.shared.increase()
        XCTAssertEqual(TextScaleManager.shared.scale, 1 + TextScaleManager.step, accuracy: 0.0001)
        TextScaleManager.shared.decrease()
        XCTAssertEqual(TextScaleManager.shared.scale, 1, accuracy: 0.0001)
    }

    @MainActor func testResetReturnsToOne() {
        TextScaleManager.shared.scale = TextScaleManager.maximum
        TextScaleManager.shared.reset()
        XCTAssertEqual(TextScaleManager.shared.scale, 1)
    }

    /// Both ends are reachable from the default by stepping, or the buttons would strand the
    /// user partway.
    @MainActor func testBothEndsAreReachableByStepping() {
        TextScaleManager.shared.scale = 1
        for _ in 0..<100 where TextScaleManager.shared.canIncrease { TextScaleManager.shared.increase() }
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.maximum, accuracy: 0.0001)
        for _ in 0..<100 where TextScaleManager.shared.canDecrease { TextScaleManager.shared.decrease() }
        XCTAssertEqual(TextScaleManager.shared.scale, TextScaleManager.minimum, accuracy: 0.0001)
    }

    // MARK: Label

    @MainActor func testPercentLabelIsWholePercent() {
        TextScaleManager.shared.scale = 1
        XCTAssertEqual(TextScaleManager.shared.percentLabel, "100%")
        TextScaleManager.shared.scale = 1.25
        XCTAssertEqual(TextScaleManager.shared.percentLabel, "125%")
    }

    // MARK: Propagation

    /// Changing the setting has to reach `VGFont`; that push is the only thing connecting the
    /// manager to the fonts, and nothing else would notice if it were dropped.
    @MainActor func testScaleIsPushedToVGFont() {
        TextScaleManager.shared.scale = 1.25
        XCTAssertEqual(VGFont.scale, 1.25, accuracy: 0.0001)
        TextScaleManager.shared.reset()
        XCTAssertEqual(VGFont.scale, 1, accuracy: 0.0001)
    }

    /// The window the layout can absorb, asserted so a later widening is a deliberate edit
    /// rather than a slip.
    func testBoundsAreTheDocumentedWindow() {
        XCTAssertEqual(TextScaleManager.minimum, 0.85)
        XCTAssertEqual(TextScaleManager.maximum, 1.5)
        XCTAssertGreaterThan(TextScaleManager.step, 0)
        XCTAssertLessThan(TextScaleManager.minimum, 1)
        XCTAssertGreaterThan(TextScaleManager.maximum, 1)
    }
}
