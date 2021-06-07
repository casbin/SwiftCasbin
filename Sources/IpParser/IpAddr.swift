
import Foundation


public struct Ipv4Addr:Hashable {
    public static func == (lhs: Ipv4Addr, rhs: Ipv4Addr) -> Bool {
        lhs.inner.s_addr == rhs.inner.s_addr
    }
    
    var inner: in_addr
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(inner.s_addr)
    }
    public init?(_ string:String) {
       let ipv4Addr = string.withCString { cString -> in_addr? in
            var ipv4Addr = in_addr()
            guard inet_pton(AF_INET, cString, &ipv4Addr) == 1 else {
                return nil
            }
            return ipv4Addr
       }
        
        if let ipv4 = ipv4Addr {
            self.init(ipv4)
        } else {
            return nil
        }
    }
    public init(_ c_addr: in_addr) {
        self.inner = c_addr
    }
    
    public init(_ a:UInt8,_ b:UInt8,_ c:UInt8,_ d:UInt8) {
        self.inner = .init(s_addr: UInt32.fromByte(bytes: [a,b,c,d]))
    }
    public init(octets:[UInt8]) {
       precondition(octets.count == 4, "ipv4 octets count must 4")
            self.init(octets[0], octets[1], octets[2], octets[3])
    }
    public init(ip:UInt32) {
        self.init(octets: ip.bigEndianBytes)
    }
    public func intoInner() -> in_addr {
        self.inner
    }
    public func toUint32() -> UInt32 {
        UInt32.fromByte(bytes: octets).bigEndian
    }
    public var octets:[UInt8] {
        inner.s_addr.littleEndianBytes
    }
    
}
extension Ipv4Addr :CustomStringConvertible {
    public var description: String {
        stride(from: 0, through: 24, by: 8)
            .map {
                UInt8(truncatingIfNeeded: inner.s_addr >> $0)
            }
            .map {
                String($0,radix: 10)
            }
            .joined(separator: ".")
    }
    
}


public struct Ipv6Addr:Hashable {
    public static func == (lhs: Ipv6Addr, rhs: Ipv6Addr) -> Bool {
        #if os(Linux)
        return lhs.inner.__in6_u.__u6_addr32 == rhs.inner.__in6_u.__u6_addr32
        #else
        return lhs.inner.__u6_addr.__u6_addr32 == rhs.inner.__u6_addr.__u6_addr32
        #endif
    }
    public func hash(into hasher: inout Hasher) {
        hasher.combine(segments)
    }
    
    var inner:in6_addr
    
    public init?(_ string:String) {
       let ipv6Addr = string.withCString { cString -> in6_addr? in
            var ipv6Addr = in6_addr()
            guard inet_pton(AF_INET6, cString, &ipv6Addr) == 1 else {
                return nil
            }
            return ipv6Addr
       }
        if let ipv6 = ipv6Addr {
            self.init(ipv6)
        } else {
            return nil
        }
    }
    public init(_ c_addr: in6_addr) {
        self.inner = c_addr
    }
    public func intoInner() -> in6_addr {
        self.inner
    }
    public func toUInt128() -> UInt128 {
        UInt128.fromByte(bytes: octets).bigEndian
    }
    public init(from ip:UInt128) {
        self.init(octets: ip.bigEndianBytes)
    }
    public init(octets:[UInt8]) {
        precondition(octets.count == 16, "ipv6 octets count must 16")
        #if os(Linux)
        self.inner = .init(__in6_u: .init(__u6_addr8: (octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7], octets[8], octets[9], octets[10], octets[11], octets[12], octets[13], octets[14], octets[15])))
        #else
        self.inner = .init(__u6_addr: .init(__u6_addr8: (octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7], octets[8], octets[9], octets[10], octets[11], octets[12], octets[13], octets[14], octets[15])))
        #endif
    }
    
    public var segments:[UInt16] {
        #if os(Linux)
        let cTuple = inner.__in6_u.__u6_addr16
        #else
        let cTuple = inner.__u6_addr.__u6_addr16
        #endif
    
        var segments = Array(repeating: UInt16(0), count: 8)
        (segments[0],segments[1],segments[2],segments[3],
         segments[4],segments[5],segments[6],segments[7]) = cTuple
        return segments
    }
    public var octets:[UInt8] {
        #if os(Linux)
        let cTuple = inner.__in6_u.__u6_addr8
        #else
        let cTuple = inner.__u6_addr.__u6_addr8
        #endif
        var octets:[UInt8] = Array(repeating: 0, count: 16)
        (octets[0],octets[1],octets[2],octets[3],
         octets[4],octets[5],octets[6],octets[7],
         octets[8],octets[9],octets[10],octets[11],
         octets[12],octets[13],octets[14],octets[15]) = cTuple
         return octets
    }
   
    // `::ffff:a.b.c.d` becomes `a.b.c.d`.
    public var mappedIpv4: Ipv4Addr? {
        if octets[10] == 0xff && octets[11] == 0xff {
            return .init(octets[12], octets[13], octets[14], octets[15])
        }
        return nil
    }
    // "::a.b.c.d" and "::ffff:a.b.c.d" become "a.b.c.d"
    public func toIpv4() -> Ipv4Addr? {
        if segments[5] == 0 || segments[5] == 0xffff {
            let ab = segments[6].littleEndianBytes
            let cd = segments[7].littleEndianBytes
            return .init(ab[0], ab[1], cd[0], cd[1])
        }
        return nil
    }
}

extension Ipv6Addr: CustomStringConvertible {
    public var description: String {
        segments.map {
            String($0,radix: 16)
        }.joined(separator: ":")
    }
}


public enum IpAddr:Hashable {
    case V4(Ipv4Addr)
    case V6(Ipv6Addr)
    
    public init(_ ipv6:in6_addr) {
        self = .V6(.init(ipv6))
    }
    public init(_ ipv4:in_addr) {
        self = .V4(.init(ipv4))
    }
    public init?(_ string:String) {
        if let ipv6 = Ipv6Addr.init(string) {
            self = .V6(ipv6)
        } else if let ipv4 = Ipv4Addr.init(string) {
            self = .V4(ipv4)
        } else {
            return nil
        }
    }
    
    
    public var isIpv4:Bool {
        switch self {
         
        case .V4:
            return true
        case .V6:
            return false
        }
    }
    public var isIpv6: Bool {
        switch self {
         
        case .V4:
            return false
        case .V6:
            return true
        }
    }
    
    public init(ipv4:Ipv4Addr){
        self = .V4(ipv4)
    }
    public init(ipv6:Ipv6Addr){
        self = .V6(ipv6)
    }
    public init(octets:[UInt8])  {
        precondition(octets.count == 4 || octets.count == 16, "ipv4 octets count must 4,ipv6 octets count must 16")
        if octets.count == 4 {
            self = .V4(.init(octets: octets))
        } else {
            self = .V6(.init(octets: octets))
        }
    }
}
