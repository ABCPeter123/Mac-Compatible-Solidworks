// Independent, hardware-accelerated macOS Metal render-to-texture test.
// Does not use SOLIDWORKS, Wine, or an OpenGL implementation.
import Foundation
import Metal

func fail(_ stage: String) -> Never {
    print("SWCOMPAT_METAL_RENDER_STAGE=\(stage)")
    print("SWCOMPAT_METAL_RENDER=FAIL")
    exit(1)
}

guard let device = MTLCreateSystemDefaultDevice() else {
    fail("MTLCreateSystemDefaultDevice")
}
print("SWCOMPAT_METAL_RENDER_DEVICE=\(device.name)")
guard let queue = device.makeCommandQueue() else {
    fail("makeCommandQueue")
}

let width = 64
let height = 64
let descriptor = MTLTextureDescriptor.texture2DDescriptor(
    pixelFormat: .rgba8Unorm, width: width, height: height, mipmapped: false
)
descriptor.textureType = .type2D
descriptor.storageMode = .shared
descriptor.usage = [.renderTarget]
guard let texture = device.makeTexture(descriptor: descriptor) else {
    fail("makeTexture")
}

let renderPass = MTLRenderPassDescriptor()
renderPass.colorAttachments[0].texture = texture
renderPass.colorAttachments[0].loadAction = .clear
renderPass.colorAttachments[0].storeAction = .store
renderPass.colorAttachments[0].clearColor = MTLClearColor(
    red: 0.25, green: 0.5, blue: 0.75, alpha: 1.0
)
guard let buffer = queue.makeCommandBuffer() else {
    fail("makeCommandBuffer")
}
guard let encoder = buffer.makeRenderCommandEncoder(descriptor: renderPass) else {
    fail("makeRenderCommandEncoder")
}
encoder.endEncoding()
buffer.commit()
buffer.waitUntilCompleted()
guard buffer.status == .completed else {
    print("SWCOMPAT_METAL_RENDER_ERROR=\(String(describing: buffer.error))")
    fail("CommandBufferNotCompleted")
}

var pixels = [UInt8](repeating: 0, count: width * height * 4)
pixels.withUnsafeMutableBytes { data in
    guard let destination = data.baseAddress else { return }
    texture.getBytes(
        destination,
        bytesPerRow: width * 4,
        from: MTLRegionMake2D(0, 0, width, height),
        mipmapLevel: 0
    )
}
let position = (height / 2 * width + width / 2) * 4
let pixel = Array(pixels[position..<(position + 4)])
print("SWCOMPAT_METAL_RENDER_PIXEL=\(pixel.map(String.init).joined(separator: ","))")
let expected = [64, 128, 191, 255]
let valid = zip(pixel, expected).allSatisfy {
    abs(Int($0.0) - $0.1) <= 2
}
guard valid else {
    fail("PixelReadbackMismatch")
}
print("SWCOMPAT_METAL_RENDER=PASS")
