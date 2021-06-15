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

import NIO
public final class DefaultModel {
    var model: [String:[String:Assertion]] = [:]
    public static func from(file:String,fileIo:NonBlockingFileIO,on eventloop:EventLoop) -> EventLoopFuture<DefaultModel> {
        Config.from(file: file,fileIo: fileIo,on: eventloop).flatMap {
            let model = DefaultModel.init()
            for sec in ["r","p","e","m","g"] {
                let r =  model.loadSection(cfg: $0, sec: sec)
                if case .failure(let e) = r {
                    return eventloop.makeFailedFuture(e)
                }
            }
            return eventloop.makeSucceededFuture(model)
        }
    }
    public static func from(text:String,on eventloop:EventLoop) -> EventLoopFuture<DefaultModel> {
        Config.from(text: text, on: eventloop).flatMap {
            let model = DefaultModel.init()
            for sec in ["r","p","e","m","g"] {
                let r =  model.loadSection(cfg: $0, sec: sec)
                if case .failure(let e) = r {
                    return eventloop.makeFailedFuture(e)
                }
            }
            return eventloop.makeSucceededFuture(model)
        }
        
    }
    public init() {
        
    }
    func loadSection(cfg:Config,sec:String) -> CasbinResult<Void> {
        var i = 1
        while true {
            if case let .success(b) = loadAssertion(cfg: cfg, sec: sec, key: "\(sec)\(getKeySuffix(i: i))"),b == false {
                break
            } else {
                i += 1
            }
        }
        return .success(())
    }
    
    func loadAssertion(cfg:Config,sec:String,key:String) -> CasbinResult<Bool> {
        var secName:CasbinResult<String> {
            switch sec {
            case "r":
                return .success("request_definition")
            case "p":
                return .success("policy_definition")
            case "g":
                return .success("role_definition")
            case "e":
                return .success("policy_effect")
            case "m":
                return .success("matchers")
            default:
                return .failure(.MODEL_ERROR(.Other("Unknown section:\(sec)")))
            }
        }
        return secName.map { s in
            let val = cfg.get(key: "\(s)::\(key)")
            if val.isEmpty {
                return false
            }
            return addDef(sec: sec, key: key, value: val)
        }
    }
    func getKeySuffix(i:Int) -> String {
        i == 1 ? "" : String(i)
    }
}

extension DefaultModel:Model {
    public func getModel() -> [String : [String : Assertion]] {
        self.model
    }
    
    
    public func addDef(sec:String,key:String,value:String) -> Bool {
        let ast = Assertion.init(key: key, value: Util.removeComment(value))
        if ast.value.isEmpty {
            return false
        }
        if sec == "r" || sec == "p" {
            ast.tokens = ast
                .value
                .split(separator: ",")
                .map {
                    "\(key)_\($0.trimmingCharacters(in: .whitespaces))"
                }
        } else {
            ast.value = Util.escapeAssertion(ast.value)
        }
        var new = model.getOrInsert(key: sec, with: [:])
        new[key] = ast
        model.updateValue(new, forKey: sec)
        return true
    }
    
    public func buildRolelinks(rm:RoleManager) -> CasbinResult<Void> {
        if let asts = model["g"] {
            for ast in asts.values {
              let r = ast.buildRolelinkes(rm: rm)
                switch r {
                case .success:
                    continue
                case .failure(let e):
                    return .failure(e)
                }
            }
        }
        return .success(())
    }
    public func buildIncrementalRoleLinks(
        rm:RoleManager,
        eventData:EventData)-> CasbinResult<Void> {
        
        var ast: Assertion? {
            switch eventData {
            case let .AddPolicy(sec, ptype, _),
                 let .AddPolicies(sec, ptype, _),
                 let .RemovePolicy(sec, ptype, _),
                 let .RemovePolicies(sec, ptype, _),
                 let .RemoveFilteredPolicy(sec, ptype, _) :
                if sec == "g" {
                    return model[sec]?[ptype]
                } else {
                    return nil
                }
            default:
                return nil
            }
        }
        if let ast = ast {
            return ast.buildIncrementalRoleLinks(rm: rm, eventData: eventData)
        }
        return .success(())
    }
    
    public  func addPolicy(sec:String,ptype:String,rule:[String]) -> Bool {
        if let ast = model[sec]?[ptype] {
            ast.policy.append(rule)
            return true
        }
        return false
    }
    public func addPolicies(sec:String,ptype:String,rules:[[String]]) -> Bool {
        var allAdded = true
        if let ast = model[sec]?[ptype] {
            for rule in rules {
                if ast.policy.contains(rule) {
                    allAdded = false
                    return allAdded
                }
            }
            ast.policy.append(contentsOf: rules)
        }
        return allAdded
    }
    public func getPolicy(sec:String,ptype:String) -> [[String]] {
        if let ast = model[sec]?[ptype] {
           return ast.policy
        }
        return []
    }
    
    public func getFilteredPolicy(sec:String,
                           ptype:String,
                           fieldIndex:Int,
                           fieldValues:[String])-> [[String]] {
        var res:[[String]] = []
        if let ast = model[sec]?[ptype] {
            for rule in ast.policy {
                var matched = true
                for (i,fieldValue) in fieldValues.enumerated() {
                    if !fieldValue.isEmpty
                        && rule[fieldIndex + i] != fieldValue {
                       matched = false
                       break
                    }
                }
                if matched {
                    res.append(rule)
                }
            }
        }
        return res
    }
    public func hasPolicy(sec:String,ptype:String,rule:[String]) -> Bool {
        getPolicy(sec: sec, ptype: ptype).contains(rule)
    }
 
        public func getValuesForFieldInPolicy(sec:String,ptype:String,fieldIndex:Int) -> [String]  {
            let policy = getPolicy(sec: sec, ptype: ptype).reduce(into: Set<String>()) { acc, x in
            acc.insert(x[fieldIndex])
          }
          return Array(policy)
      }
    
    public func removePolicy(sec:String,ptype:String,rule: [String]) -> Bool {
       if let ast = model[sec]?[ptype] {
        ast.policy.removeAll {
            $0 == rule
         }
        return true
        }
        return false
    }
    public func removePolicies(sec:String,ptype:String,rules:[[String]]) -> Bool {
        var allRemoved = true
        if let ast = model[sec]?[ptype] {
            for rule in rules {
                if ast.policy.contains(rule) {
                    allRemoved = false
                    return allRemoved
                }
            }
            for rule in rules {
                ast.policy.removeAll { $0 == rule }
            }
        }
        return allRemoved
    }
    
    public  func clearPolicy() {
        if let modelP = model["p"] {
            modelP.values.forEach {
                $0.policy.removeAll()
            }
        }
        if let modelG = model["g"] {
            modelG.values.forEach {
                $0.policy.removeAll()
            }
        }
    }
    public func removeFilteredPolicy(
        sec:String,
        ptype:String,
        fieldIndex:Int,
        fieldValues:[String]
    ) -> (Bool,[[String]]) {
        if fieldValues.isEmpty {
            return (false,[])
        }
        var res = false
        var rulesRemoved:[[String]] = []
        if let ast = model[sec]?[ptype] {
            for rule in ast.policy {
                var matched = true
                for (i,fieldValue) in fieldValues.enumerated() {
                    if !fieldValue.isEmpty
                        && rule[fieldIndex + i] != fieldValue {
                       matched = false
                       break
                    }
                }
                if matched {
                    res = true
                    rulesRemoved.append(rule)
                }
            }
            if res && !rulesRemoved.isEmpty {
                for rule in rulesRemoved {
                    ast.policy.removeAll { $0 == rule}
                }
            }
        }
        return (res,rulesRemoved)
    }
}
