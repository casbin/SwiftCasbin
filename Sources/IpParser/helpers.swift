

import Foundation

func bitLength(number:UInt32) -> UInt8 {
    UInt8(32 - number.leadingZeroBitCount)
}

func biteMask(mask:UInt8) -> UInt32 {
    assert(mask <= 32)
    switch mask {
    case 0:
        return 0
    default:
        return ~0 << (32 - mask)
    }
}
func biteMaskU128(mask: UInt8) -> UInt128 {
    assert(mask <= 128)
    switch mask {
    case 0:
        return 0
    default:
        return ~0 << (128 - mask)
    }
}

func splitIpNetmask(_ input: String) -> (String,String)? {
   let net = input.split(separator: "/", maxSplits: 2)
    if net.count < 2 {
        return nil
    }
    let ip = String(net[0])
    let mask = String(net[1])
    if ip.isEmpty || mask.isEmpty {
        return nil
    } else {
        return (String(net[0]),String(net[1]))
    }
}

extension FixedWidthInteger where Self:UnsignedInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: self.bigEndian) {
            [UInt8]($0)
        }
    }
    var littleEndianBytes:[UInt8] {
        withUnsafeBytes(of: self.littleEndian) {
            [UInt8]($0)
        }
    }
    
    //        let count = MemoryLayout<Self>.size
    //        return stride(from: (count - 1) * 8, through: 0, by: -8).map {
    //           let s = UInt8(truncatingIfNeeded: self >> $0)
    //            return s

 static func fromByte(bytes: [UInt8]) -> Self {
    casting(bytes: bytes, to: Self.self)
    //        precondition(bytes.count == MemoryLayout<Self>.size, "betys array count error:must \(MemoryLayout<Self>.size ) but got \(bytes.count)")
    //        let x = stride(from: (bytes.count - 1) * 8, through: 0, by: -8)
    //            .map { step -> Self in
    //                return  Self(bytes[bytes.count - 1 - step / 8]) << step
    //            }
    //        return x.reduce(x[0]) { $0 | $1}
   }
}


func casting<R:FixedWidthInteger>(bytes:[UInt8],to target:R.Type) -> R {
    var bytes = bytes
    precondition(bytes.count == MemoryLayout<R>.size, "betys array count error:must \(MemoryLayout<R>.size ) but got \(bytes.count)")
    guard let result = bytes.withContiguousMutableStorageIfAvailable({ $0.withUnsafeBytes {
        $0.baseAddress!.assumingMemoryBound(to: R.self).pointee
    }
    }) else {
        return bytes.withUnsafeBytes {
            $0.baseAddress!.assumingMemoryBound(to: R.self).pointee
        }
    }
    return result
}
