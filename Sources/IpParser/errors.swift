public enum IpNetworkError:CustomStringConvertible,Error {
    public var description: String {
        switch self {
        
        case .NetmaskError(let mask):
            return "invalid netmask \(mask)"
        case .HostBitsSet:
            return "IP network address has host bits set"
        }
    }
    
    /// Network mask is bigger than possible for given IP version (32 for IPv4, 128 for IPv6).
    case NetmaskError(UInt8)
    /// Host bits are set in given network IP address.
    case HostBitsSet
    
}

public enum IpNetworkParseError: CustomStringConvertible,Error {
    public var description: String {
        switch self {
       
        case .InvalidNetmaskFormat:
            return "invalid netmask format"
        case .InvalidFormatError:
            return "invalid format"
        case .AddrParseError:
            return "invalid IP address syntax"
        case .IpNetworkError(let e):
            return e.description
        }
    }
    
    /// Network mask is not valid integer between 0 and 255.
       case InvalidNetmaskFormat
        /// Network address has invalid format (not X/Y).
       case InvalidFormatError
        /// Invalid IP address syntax (IPv4 or IPv6).
       case AddrParseError
        /// Error when creating new IPv4 or IPv6 networks.
       case IpNetworkError(IpNetworkError)
}
