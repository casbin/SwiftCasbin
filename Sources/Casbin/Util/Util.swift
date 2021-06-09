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

import Expression
import Regex

public typealias MatchFunction = (String,String) -> Bool
public typealias ExpressionFunction = ([Any]) throws -> Bool


public struct Util {
    
    static func validateVariadicArgs(expentedLen: Int,args: [Any]) -> CasbinError? {
        if args.count != expentedLen {
            return .MATCH_ERROR(.MatchFuntionArgsCountError(args.count))
        }
        for p in args {
            if !(p is String) {
                return .MATCH_ERROR(.MatchFuntionArgsNotString)
            }
        }
        return nil
    }
    
    public static func escapeAssertion(_ s:String) -> String {
        var _s = s
        _s.replaceAll(matching: #"\b(r\d*|p\d*)\."#, with: "$1_")
        return _s
    }
    public static func removeComment(_ s: String) -> String {
        var _s:String {
            if let i =  s.firstIndex(of: "#") {
                return String(s[..<i])
            } else {
                return s
            }
        }
        return _s.trimmingCharacters(in: .whitespaces)
    }
    
    public static func escapeEval(_ m:String) -> String {
        let re = Regex.init(#"\beval\(([^)]*)\)"#)
        var _m = m
        _m.replaceAll(matching: re, with: "eval($1)")
        return _m
    }
    
    public static func parseCsvLine(line: String) -> [String]? {
        let line = line.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.starts(with: "#") {
            return nil
        }
        let re = Regex(#"(\s*"[^"]*"?|\s*[^,]*)"#)
        var res:[String] = []
        let s = re.allMatches(in: line).map { $0.matchedString.trimmingCharacters(in: .whitespaces) }
        for col in s {
            if  !col.isEmpty {
                if col.count >= 2
                    && col.starts(with: "\"")
                    && col.hasSuffix("\"") {
                    res.append(String(col[col.index(after: col.startIndex)..<col.index(before: col.endIndex)]))
                } else {
                    res.append(col)
                }
            }
        }
        if res.isEmpty {
            return nil
        } else {
            return res
        }
    }
    public static func loadPolicyLine(line:String,m:Model) {
        if line.isEmpty || line.starts(with: "#") {
            return
        }
        if let tokens = Util.parseCsvLine(line: line),!tokens.isEmpty {
            let key = tokens[0]
            if let sec = key.first {
                if let item = m.getModel()[String(sec)] {
                    if let ast = item[key] {
                        ast.policy.append(Array(tokens[1...]))
                    }
                }
            }
        }
    }
   public static func loadFilteredPolicyLine(line:String,m:Model,f:Filter) -> Bool {
        if line.isEmpty || line.starts(with: "#") {
            return false
        }
        if let tokens = Util.parseCsvLine(line: line) {
            let key = tokens[0]
            var isFiltered = false
            if let sec = key.first {
                let sec = String(sec)
                if sec == "p" {
                    for (i,rule) in f.p.enumerated() {
                        if !rule.isEmpty && rule != tokens[i + 1] {
                            isFiltered = true
                        }
                    }
                }
                if sec == "g" {
                    for (i,rule) in f.g.enumerated() {
                        if !rule.isEmpty && rule != tokens[i + 1] {
                            isFiltered = true
                        }
                    }
                }
                if !isFiltered {
                    if let ast = m.getModel()[sec]?[key] {
                        ast.policy.append(Array(tokens[1...]))
                    }
                }
                
            }
            return isFiltered
        }else {
            return false
        }
    }
    
 
    
    
}


