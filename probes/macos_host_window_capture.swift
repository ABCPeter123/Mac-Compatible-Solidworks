// Original, self-contained macOS host window screenshot calibration and Wine capture.
// Runs ONLY on a graphical macOS session and NEVER saves screenshots as artifacts.
// Prints fixed status enums, no window titles, user paths, pixel arrays, or logs.
// A successful Wine result proves pixel content in a macOS window screenshot,
// not physical Mac input, native SOLIDWORKS, or GPU-accelerated performance.
import AppKit
import CoreGraphics
import Foundation

private let wineTitle = "SWCompat Windows GUI session"
private let controlTitle = "SWCompat Native Capture Control"
private let outputKeys = ["SCHEMA", "MODE", "WINDOW", "CAPTURE", "PIXEL"]

private func output(_ mode: String, _ window: String,
                    _ capture: String, _ pixel: String) {
    let values = ["1", mode, window, capture, pixel]
    for (name, value) in zip(outputKeys, values) {
        print("SWCOMPAT_HOST_PIXELS_\(name)=\(value)")
    }
    fflush(stdout)
}
private func findWindow(title: String) -> CGWindowID? {
    guard let windows = CGWindowListCopyWindowInfo(
        [.optionOnScreenOnly, .excludeDesktopElements],
        CGWindowID(0)) as? [[String: Any]] else {
        return nil
    }
    for item in windows {
        if (item[kCGWindowName as String] as? String) == title,
           let number = item[kCGWindowNumber as String] as? NSNumber {
            return CGWindowID(number.uint32Value)
        }
    }
    return nil
}
private func capture(_ id: CGWindowID, target: (Int, Int, Int)) -> (String, String) {
    // tempfile contains ONLY our synthetic window, never the desktop.
    let location = FileManager.default.temporaryDirectory
        .appendingPathComponent("swcompat-pixels-" + UUID().uuidString + ".png")
    defer { try? FileManager.default.removeItem(at: location) }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    process.arguments = ["-x", "-l", String(id), location.path]
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return ("UNAVAILABLE", "NOT_TESTED")
    }
    if process.terminationStatus != 0 {
        return ("UNAVAILABLE", "NOT_TESTED")
    }
    guard let bytes = try? Data(contentsOf: location),
          let bitmap = NSBitmapImageRep(data: bytes),
          bitmap.pixelsWide >= 50, bitmap.pixelsHigh >= 50,
          let sampled = bitmap.colorAt(x: bitmap.pixelsWide / 2,
                                      y: bitmap.pixelsHigh / 2)?
              .usingColorSpace(NSColorSpace.deviceRGB) else {
        return ("UNAVAILABLE", "NOT_TESTED")
    }
    let observed = [Int((sampled.redComponent * 255).rounded()),
                    Int((sampled.greenComponent * 255).rounded()),
                    Int((sampled.blueComponent * 255).rounded())]
    let expected = [target.0, target.1, target.2]
    let equal = zip(observed, expected).allSatisfy {
        abs($0.0 - $0.1) <= 32
    }
    return ("SUCCESS", equal ? "PASS" : "MISMATCH")
}
private final class CalibrationView: NSView {
    override func draw(_ dirtyRect: NSRect) {
        NSColor(calibratedRed: 40.0 / 255, green: 190.0 / 255,
                blue: 80.0 / 255, alpha: 1).setFill()
        NSBezierPath(rect: bounds).fill()
    }
}
private func nativeControl() {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    app.finishLaunching()
    let frame = NSRect(x: 80, y: 80, width: 440, height: 370)
    let window = NSWindow(contentRect: frame,
                          styleMask: [.titled, .closable],
                          backing: .buffered, defer: false)
    window.title = controlTitle
    window.isReleasedWhenClosed = false
    let referenceColor = NSColor(
        calibratedRed: 40.0 / 255, green: 190.0 / 255,
        blue: 80.0 / 255, alpha: 1)
    window.backgroundColor = referenceColor
    window.isOpaque = true
    let content = CalibrationView(frame: frame)
    window.contentView = content
    window.makeKeyAndOrderFront(nil)
    app.activate(ignoringOtherApps: true)
    content.needsDisplay = true
    window.displayIfNeeded()
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 1.25))
    window.displayIfNeeded()
    let id = CGWindowID(window.windowNumber)
    let result = capture(id, target: (40, 190, 80))
    output("NATIVE", "FOUND", result.0, result.1)
    window.close()
}
private func wineWindow() {
    var selected: CGWindowID? = nil
    for _ in 0..<12 {
        if let found = findWindow(title: wineTitle) {
            selected = found
            break
        }
        Thread.sleep(forTimeInterval: 0.25)
    }
    guard let id = selected else {
        output("WINE", "NOT_FOUND", "UNAVAILABLE", "NOT_TESTED")
        return
    }
    let result = capture(id, target: (30, 209, 38))
    output("WINE", "FOUND", result.0, result.1)
}
guard CommandLine.arguments.count == 2 else {
    output("INVALID", "NOT_FOUND", "UNAVAILABLE", "NOT_TESTED")
    exit(2)
}
switch CommandLine.arguments[1] {
case "native":
    nativeControl()
case "wine":
    wineWindow()
default:
    output("INVALID", "NOT_FOUND", "UNAVAILABLE", "NOT_TESTED")
    exit(2)
}
