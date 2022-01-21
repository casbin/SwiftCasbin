// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import Regex
import IpParser

extension Util {
    /// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a "＊".
    /// For example, "/foo/bar" matches "/foo/＊"
    public static func keyMatch(_ key1: String,_ key2: String) -> Bool {
        guard let any = key2.firstIndex(of: "*") else {
            return key1 == key2
        }
        let k = key2[..<any]
        
        if key1.count > k.count {
            return key1[..<any] == k
        }
        return key1 == k
    }
    
    public static func toExpressionFunction(name:String,function:@escaping MatchFunction) -> ExpressionFunction {
        return { (args) throws -> Bool in
            if let err = validateVariadicArgs(expentedLen: 2, args: args) {
                throw CasbinError.OtherErrorMessage("\(name):\(err.description)")
            }
            let name1 = args[0] as! String
            let name2 = args[1] as! String
            return function(name1, name2)
        }
    }
    
    ///  regexMatch determines whether key1 matches the pattern of key2 in regular expression.
    /// - Parameters:
    ///   - key1: key1
    ///   - key2:  regular expression
    public static func regexMatch(_ key1: String,_ key2: String) -> Bool {
        do {
            return try Regex.init(string: key2).matches(key1)
        } catch  {
            preconditionFailure("unexpected error creating regex: \(error)")
        }
    }
    // key_match2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
    // For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
    public static func keyMatch2(_ key1:String,_ key2: String) -> Bool {
        var key2 = key2.contains("/*")
            ? key2.replacingOccurrences(of: "/*", with: "/.*")
            : key2
        
        while key2.contains("/:") {
            key2 = key2.replacingAll(matching: #":[^/]+"#, with: #"[^/]+"#)
        }
        return regexMatch(key1, "^\(key2)$")
    }
    // key_match3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
    // For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
    public static func keyMatch3(_ key1:String,_ key2: String) -> Bool {
        var key2 = key2.contains("/*")
            ? key2.replacingOccurrences(of: "/*", with: "/.*")
            : key2
        
        while key2.contains("/{") {
            key2 = key2.replacingAll(matching: #"\{[^/]+\}"#, with: #"[^/]+"#)
        }
        return regexMatch(key1, "^\(key2)$")
    }
    public static func ipMatch(_ key1:String,_ key2: String) -> Bool {
        let key2Split = key2.split(separator: "/")
        let ipAddr2 = String(key2Split[0])
        guard let ipAddr1 = IpAddr.init(key1),let ipAddr2 = IpAddr.init(ipAddr2) else {
           fatalError("invalid argument \(key1),\(key2)")
        }
        if key2Split.count == 2 {
            switch UInt8(key2Split[1]) {
            case .some(let netmask):
                switch IpNetwork.newTruncate(networkAddress: ipAddr2, netmask: netmask) {
                case .success(let network):
                    return network.contains(ip: ipAddr1)
                case .failure(let e) :
                    fatalError("invalid ip netmask \(e.description)")
                }
            default:
                fatalError("invalid netmask \(key2Split[1])")
            }
        } else {
            if case let (.V4(ip1),.V6(ip2)) = (ipAddr1,ipAddr2) {
                if let ip2 = ip2.toIpv4() {
                    return ip2 == ip1
                }
            }
            return ipAddr1 == ipAddr2
        }
    }
    // GlobMatch determines whether key1 matches the pattern of key2 using glob pattern
    public static func globMatch(_ key1:String,_ key2: String) -> Bool {
        let key1Split = key1.split(separator: "/")
        var key2Split = key2.split(separator: "/")
        if key2Split.count > 0 && key2Split[0] == "*" {
            key2Split.removeFirst()
        }
        if key1Split.count != key2Split.count {
            return false
        } else {
            for i in 0..<key1Split.count {
                if !glob(s: String(key1Split[i]), p: String(key2Split[i])) {
                    return false
                }
            }
            return true
        }
    }
    private static func glob(s: String, p: String) -> Bool {
        var s = s
        var p = p
        while s.count > 0 && p.count > 0 && p[p.index(p.endIndex, offsetBy: -1)] != "*" {
            if s[s.index(s.endIndex, offsetBy: -1)] == p[p.index(p.endIndex, offsetBy: -1)] {
                s = String(s[s.startIndex..<s.index(s.endIndex, offsetBy: -1)])
                p = String(p[p.startIndex..<p.index(p.endIndex, offsetBy: -1)])
            } else {
                return false
            }
        }
        if p.count == 0 {
            return s.count == 0
        }
        var sIndex = 0
        var pIndex = 0
        var sRecord = -1
        var pRecord = -1
        while sIndex < s.count && pRecord < p.count {
            if p[p.index(p.startIndex, offsetBy: pIndex)] == "*" {
                pIndex += 1
                sRecord = sIndex
                pRecord = pIndex
            } else if s[s.index(s.startIndex, offsetBy: sIndex)] == p[p.index(p.startIndex, offsetBy: pIndex)] {
                sIndex += 1
                pIndex += 1
            } else if sRecord != -1 && sRecord + 1 < s.count {
                sRecord += 1
                sIndex = sRecord
                pIndex = pRecord
            } else {
                return false
            }
        }
        while pIndex < p.count {
            if p[p.index(p.startIndex, offsetBy: pIndex)] != "*" {
                return false
            }
            pIndex += 1
        }
        return true
    }
}
