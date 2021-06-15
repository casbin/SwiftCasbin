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
public extension CoreApi {
    //MARK:ManagementApi
    func addNamedPolicy(ptype:String,params:[String]) -> EventLoopFuture<Bool> {
        addPolicyInternal(sec: "p", ptype: ptype, rule: params)
    }
    func addNamedPolicies(ptype:String,paramss:[[String]]) -> EventLoopFuture<Bool> {
        addPoliciesInternal(sec: "p", ptype: ptype, rules: paramss)
    }
    func removeNamedPolicy(ptype:String,params:[String]) -> EventLoopFuture<Bool> {
        removePolicyInternal(sec: "p", ptype: ptype, rule: params)
    }
    func removeNamedPolicies(ptype:String,paramss:[[String]]) -> EventLoopFuture<Bool> {
        removePoliciesInternal(sec: "p", ptype: ptype, rules: paramss)
    }
    func addNamedGroupingPolicy(ptype:String,params:[String]) -> EventLoopFuture<Bool> {
        addPolicyInternal(sec: "g", ptype: ptype, rule: params)
    }
    func addNamedGroupingPolicies(ptype:String,paramss:[[String]]) -> EventLoopFuture<Bool> {
        addPoliciesInternal(sec: "g", ptype: ptype, rules: paramss)
    }
    func removeNamedGroupingPolicy(ptype:String,params:[String]) -> EventLoopFuture<Bool> {
        removePolicyInternal(sec: "g", ptype: ptype, rule: params)
    }
    func removeNamedGroupingPolicies(ptype:String,paramss:[[String]]) -> EventLoopFuture<Bool> {
        removePoliciesInternal(sec: "g", ptype: ptype, rules: paramss)
    }
    func removeFilteredNamedGroupingPolicy(ptype:String,
                                           fieldIndex:Int,
                                           fieldValues:[String])
                                             -> EventLoopFuture<Bool> {
        removeFilteredPolicyInternal(sec: "g", ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues).map {
            $0.0
        }
    }
    func removeFilteredNamedPolicy(ptype:String,
                                           fieldIndex:Int,
                                           fieldValues:[String])
                                             -> EventLoopFuture<Bool> {
        removeFilteredPolicyInternal(sec: "p", ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues).map {
            $0.0
        }
    }
    func getNamedPolicy(ptype:String) -> [[String]] {
        model.getPolicy(sec: "p", ptype: ptype)
    }
    
    func getAllPolicy() -> [[String]] {
        var res: [[String]] = []
        if let asts = model.getModel()["p"] {
            asts.forEach { (key: String, value: Assertion) in
                let ast = value.policy.map { rules -> [String] in
                    var rules = rules
                    rules.insert(key, at: 0)
                    rules.insert("p", at: 0)
                    return rules
                }
                res.append(contentsOf: ast)
            }
        }
        return res
    }
    func getFilteredNamedPolicy(ptype:String,fieldIndex:Int,fieldValues:[String]) -> [[String]] {
        model.getFilteredPolicy(sec: "p", ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues)
    }
    func hasNamedPolicy(ptype:String,params:[String]) -> Bool {
        model.hasPolicy(sec: "p", ptype: ptype, rule: params)
    }
    func getNamedGroupingPolicy(ptype:String) -> [[String]] {
        model.getPolicy(sec: "g", ptype: ptype)
    }
    func getAllGroupingPolicy() -> [[String]] {
        var res: [[String]] = []
        if let asts = model.getModel()["g"] {
            asts.forEach { (key: String, value: Assertion) in
                let ast = value.policy.map { rules -> [String] in
                    var rules = rules
                    rules.insert(key, at: 0)
                    rules.insert("g", at: 0)
                    return rules
                }
                res.append(contentsOf: ast)
            }
        }
        return res
        
    }
    func getFilteredNamedGroupingPolicy(ptype:String,fieldIndex:Int,fieldValues:[String]) -> [[String]] {
        model.getFilteredPolicy(sec: "g", ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues)
    }
    func hasGroupingNamedPolicy(ptype:String,params:[String]) -> Bool {
        model.hasPolicy(sec: "g", ptype: ptype, rule: params)
    }
    func getAllNamedSubjects(ptype:String) -> [String] {
        model.getValuesForFieldInPolicy(sec: "p", ptype: ptype, fieldIndex:model.getModel()["p"]?["p"]?.tokens.firstIndex(of: "p_sub") ?? 0)
    }
    func getAllNamedObjects(ptype:String) -> [String] {
        model.getValuesForFieldInPolicy(sec: "p", ptype: ptype, fieldIndex:model.getModel()["p"]?["p"]?.tokens.firstIndex(of: "p_obj") ??  1)
    }
    func getAllNamedActions(ptype:String) -> [String] {
        model.getValuesForFieldInPolicy(sec: "p", ptype: ptype, fieldIndex:model.getModel()["p"]?["p"]?.tokens.firstIndex(of: "p_act") ??  2)
    }
    func getAllNamedRoles(ptype:String) -> [String] {
        model.getValuesForFieldInPolicy(sec: "g", ptype: ptype, fieldIndex: 1)
    }
    
}

public extension CoreApi {
    func addPolicy(params:[String]) -> EventLoopFuture<Bool> {
        addNamedPolicy(ptype: "p", params: params)
    }
    func addPolicies(paramss:[[String]]) -> EventLoopFuture<Bool> {
        addNamedPolicies(ptype: "p", paramss: paramss)
    }
    func removePolicy(params:[String]) -> EventLoopFuture<Bool> {
        removeNamedPolicy(ptype: "p", params: params)
    }
    func removePolicies(paramss:[[String]]) -> EventLoopFuture<Bool> {
        removeNamedPolicies(ptype: "p", paramss: paramss)
    }
    func addGroupingPolicy(params:[String]) -> EventLoopFuture<Bool> {
        addNamedGroupingPolicy(ptype: "g", params: params)
    }
    func addGroupingPolicies(paramss:[[String]]) -> EventLoopFuture<Bool> {
        addNamedGroupingPolicies(ptype: "g", paramss: paramss)
    }
    func removeGroupingPolicy(params:[String]) -> EventLoopFuture<Bool> {
        removeNamedGroupingPolicy(ptype: "g", params: params)
    }
    func removeGroupingPolicies(paramss:[[String]]) -> EventLoopFuture<Bool> {
        removeNamedGroupingPolicies(ptype: "g", paramss: paramss)
    }
    func removeFilteredPolicy(fieldIndex:Int,
                              fieldValues:[String])
                                             -> EventLoopFuture<Bool> {
        removeFilteredNamedPolicy(ptype: "p", fieldIndex: fieldIndex, fieldValues: fieldValues)
    }
    func removeFilteredGroupingPolicy(fieldIndex:Int,
                              fieldValues:[String])
                                             -> EventLoopFuture<Bool> {
        removeFilteredNamedGroupingPolicy(ptype: "g", fieldIndex: fieldIndex, fieldValues: fieldValues)
    }
    func getPolicy() -> [[String]] {
        getNamedPolicy(ptype: "p")
    }
    func getFilteredPolicy(fieldIndex:Int,
                           fieldValues:[String]) -> [[String]] {
        getFilteredNamedPolicy(ptype: "p", fieldIndex: fieldIndex, fieldValues: fieldValues)
    }
    func hasPolicy(params:[String]) -> Bool {
        hasNamedPolicy(ptype: "p", params: params)
    }
    
    func getFilteredGroupingPolicy(fieldIndex:Int,
                           fieldValues:[String]) -> [[String]] {
        getFilteredNamedGroupingPolicy(ptype: "g", fieldIndex: fieldIndex, fieldValues: fieldValues)
    }
    func hasGroupingPolicy(params:[String]) -> Bool {
        hasGroupingNamedPolicy(ptype: "g", params: params)
    }
    
    
    func getAllSubjects() -> [String] {
        getAllNamedSubjects(ptype: "p")
    }
    func getAllObjects() -> [String] {
        getAllNamedObjects(ptype: "p")
    }
    func getAllActions() -> [String] {
        getAllNamedActions(ptype: "p")
    }
    func getAllRoles() -> [String] {
        getAllNamedRoles(ptype: "g")
    }
    
}

