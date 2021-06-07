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


///  * Assertion represents an expression in a section of the model.
///  * For example: r = sub, obj, act
public final class Assertion {
    public var key: String
    public var value:String
    public var tokens:[String]
    public var policy: [[String]]
    public var rm: RoleManager
    
    public init(key:String = "",
                value:String="",
                tokens:[String] = [],
                policy:[[String]] = [],
                rm: RoleManager = DefaultRoleManager.init(maxHierarchyLevel: 0)) {
        self.key = key
        self.value = value
        self.tokens = tokens
        self.policy = policy
        self.rm = rm
    }
    
    func buildRolelinkes(rm: RoleManager) -> CasbinResult<Void> {
        self.rm = rm
        let count = self.value.filter { $0  == "_" }.count
        if count < 2 {
            return .failure(.MODEL_ERROR(.P(#"the number of "_" in role definition should be at least 2"#)))
        }
        for rule in policy {
            if rule.count < count {
                return .failure(.MODEL_ERROR(.P("Policy doesn't match policy definition. expected length: \(count), found length \(rule.count)")))
            }
            if count == 2 {
                self.rm.addLink(name1: rule[0], name2: rule[1], domain: nil)
               
            } else if count == 3 {
                self.rm.addLink(name1: rule[0], name2: rule[1], domain: rule[2])
            } else {
                return .failure(.MODEL_ERROR(.P("Multiple domains are not supported")))
            }
        }
        return .success(())
    }
    
    func buildIncrementalRoleLinks(rm:RoleManager,eventData:EventData) -> CasbinResult<Void> {
        self.rm = rm
        let count = self.value.filter { $0  == "_" }.count
        if count < 2 {
            return .failure(.MODEL_ERROR(.P(#"the number of "_" in role definition should be at least 2"#)))
        }
        var d:(Bool,[[String]])? {
            switch eventData {
            case .AddPolicy(_, _, let rule):
                return (true,[rule])
            case .AddPolicies(_, _, let rules):
                return (true,rules)
            case .RemovePolicy(_, _, let rule):
                return (false,[rule])
            case .RemovePolicies(_, _, let rules):
                return (false,rules)
            case .RemoveFilteredPolicy(_, _, let rules):
                return (false,rules)
            default:
                return nil
            }
        }
        if let (insert,rules) = d {
            for rule in rules {
                if rule.count < count {
                    return .failure(.MODEL_ERROR(.P("Policy doesn't match policy definition. expected length: \(count), found length \(rule.count)")))
                }
                if count == 2 {
                    if insert {
                      self.rm.addLink(name1: rule[0], name2: rule[1], domain: nil)
                    } else {
                      return self.rm.deleteLink(name1: rule[0], name2: rule[1], domain: nil)
                    }
                }else if count == 3 {
                    if insert {
                      self.rm.addLink(name1: rule[0], name2: rule[1], domain: rule[2])
                    } else {
                      return self.rm.deleteLink(name1: rule[0], name2: rule[1], domain: rule[2])
                    }
                } else {
                    return .failure(.MODEL_ERROR(.P("Multiple domains are not supported")))
                }
            }
        }
       return .success(())
    }
}
