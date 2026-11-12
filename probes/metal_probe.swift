// Native capability probe. CI VMs may not expose GPU hardware.
import Foundation
import Metal
let devices = MTLCopyAllDevices()
print("SWCOMPAT_METAL_DEVICE_COUNT=\(devices.count)")
for (index, device) in devices.enumerated() {
    print("SWCOMPAT_METAL_DEVICE_\(index)=\(device.name)")
}
print(devices.isEmpty ? "SWCOMPAT_METAL=UNAVAILABLE" : "SWCOMPAT_METAL=AVAILABLE")
