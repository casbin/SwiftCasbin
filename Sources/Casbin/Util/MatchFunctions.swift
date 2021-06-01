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
    //TODO:IpMatch暂未实现
    public static func ipMatch(_ key1:String,_ key2: String) -> Bool {
        fatalError("未实现")
    }
    //TODO:GlobMatch暂未实现
    public static func globMatch(_ key1:String,_ key2: String) -> Bool {
        fatalError("未实现")
    }
}
