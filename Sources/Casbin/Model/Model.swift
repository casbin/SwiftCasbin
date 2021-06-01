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




public protocol Model {
    func addDef(sec:String,key:String,value:String) -> Bool
    func buildRolelinks(rm:RoleManager) -> CasbinResult<Void>
    func buildIncrementalRoleLinks(
        rm:RoleManager,
        eventData:EventData)-> CasbinResult<Void>
    func addPolicy(sec:String,ptype:String,rule:[String]) -> Bool
    func addPolicies(sec:String,ptype:String,rules:[[String]]) -> Bool
    func getPolicy(sec:String,ptype:String) -> [[String]]
    func getFilteredPolicy(sec:String,ptype:String,fieldIndex:Int,fieldValues:[String]) -> [[String]]
    func hasPolicy(sec:String,ptype:String,rule:[String]) -> Bool
    func getValuesForFieldInPolicy(sec:String,ptype:String,fieldIndex:Int) -> [String]
    func removePolicy(sec:String,ptype:String,rule: [String]) -> Bool
    func removePolicies(sec:String,ptype:String,rules:[[String]]) -> Bool
    func clearPolicy()
    func getModel() -> [String:[String:Assertion]]
    func removeFilteredPolicy(
        sec:String,
        ptype:String,
        fieldIndex:Int,
        fieldValues:[String]
    ) -> (Bool,[[String]])
}
