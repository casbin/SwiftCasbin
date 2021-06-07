
import Foundation
public struct Ipv4Network {
    var address: Ipv4Addr
    var mask: UInt8
    /// IPv4 address length in bits.
    public static let length:UInt8 = 32
    
    public static func new(address: Ipv4Addr,netmask:UInt8) -> Result<Self,IpNetworkError> {
        if netmask > Self.length {
            return .failure(.NetmaskError(netmask))
        }
       
        if address.toUint32().trailingZeroBitCount < Self.length - netmask {
            return .failure(.HostBitsSet)
        }
        return .success(.init(address: address, mask: netmask))
    }
    public static func newTruncate(address:Ipv4Addr,netmask:UInt8) -> Result<Self,IpNetworkError> {
        if netmask > Self.length {
            return .failure(.NetmaskError(netmask))
        }
        let address = Ipv4Addr.init(ip: address.toUint32() & biteMask(mask: netmask))
        return .success(.init(address: address, mask: netmask))
    }
    public var networkAddress:Ipv4Addr {
        address
    }
    public var broadcastAddress:Ipv4Addr {
      return  Ipv4Addr.init(ip: networkAddress.toUint32() | ~biteMask(mask: mask))
    }
    public var netmask:UInt8 {
        mask
    }
    // Returns network mask as IPv4 address.
    public var fullNetmask: Ipv4Addr {
        Ipv4Addr.init(ip: biteMask(mask: netmask))
    }
    public func contains(ip:Ipv4Addr) -> Bool {
        ip.toUint32() & biteMask(mask: netmask) == networkAddress.toUint32()
    }

    
    public static func from(string:String) -> Result<Ipv4Network,IpNetworkParseError> {
        guard let (ip,netmask) = splitIpNetmask(string) else {
            return .failure(.InvalidFormatError)
        }
        guard let networkAddress =  Ipv4Addr.init(ip) else {
            return .failure(.AddrParseError)
        }
        guard let netmask = UInt8(netmask) else { return .failure(.InvalidNetmaskFormat) }
        return .success(.init(address: networkAddress, mask: netmask))
        
    }
    public static func from(ip:Ipv4Addr) -> Self {
        .init(address: ip, mask: length)
    }
    
    
    
}

extension Ipv4Network: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(netmask)
        hasher.combine(networkAddress)
    }
}

public struct Ipv6Network {
    var address: Ipv6Addr
    var mask: UInt8
    public static let length:UInt8 = 32
    
    public var netmask:UInt8 {
        mask
    }
    public var networkAddress:Ipv6Addr {
        address
    }
    public static func new(address: Ipv6Addr,netmask:UInt8) -> Result<Self,IpNetworkError> {
        if netmask > Self.length {
            return .failure(.NetmaskError(netmask))
        }
       
        if address.toUInt128().trailingZeroBitCount < Self.length - netmask {
            return .failure(.HostBitsSet)
        }
        return .success(.init(address: address, mask: netmask))
    }
    public static func newTruncate(address:Ipv6Addr,netmask:UInt8) -> Result<Self,IpNetworkError> {
        if netmask > Self.length {
            return .failure(.NetmaskError(netmask))
        }
        let address = Ipv6Addr.init(from: address.toUInt128() & UInt128(biteMask(mask: netmask)))
        return .success(.init(address: address, mask: netmask))
    }
    public func contains(ip:Ipv6Addr) -> Bool {
        ip.toUInt128() & UInt128(biteMask(mask: netmask)) == networkAddress.toUInt128()
    }
}

public enum IpNetwork {
    case V4(Ipv4Network)
    case V6(Ipv6Network)
    
    public func new(networkAddress: IpAddr,netmask:UInt8) -> Result<Self,IpNetworkError> {
        switch networkAddress {
        case .V4(let ip):
            return Ipv4Network.new(address: ip, netmask: netmask).map {
                .V4($0)
            }
        case .V6(let ip):
           return Ipv6Network.new(address: ip, netmask: netmask).map {
                .V6($0)
            }
        }
    }
    public static func newTruncate(networkAddress:IpAddr,netmask:UInt8) -> Result<Self, IpNetworkError>{
        switch networkAddress {
        case .V4(let ip):
            return Ipv4Network.newTruncate(address: ip, netmask: netmask).map {
                .V4($0)
            }
        case .V6(let ip):
           return Ipv6Network.newTruncate(address: ip, netmask: netmask).map {
                .V6($0)
            }

        }
    }
    public func contains(ip:IpAddr) -> Bool {
        switch (self,ip) {
        case (.V4(let network),.V4(let ip)):
            return network.contains(ip: ip)
        case (.V6(let network),.V6(let ip)):
            return network.contains(ip: ip)
        default:
            return false
        }
    }
}
