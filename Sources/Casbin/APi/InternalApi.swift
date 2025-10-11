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

extension CoreApi {
    //MARK: InternalApi
    func addPolicyInternal(sec:String,ptype:String,rule:[String]) -> EventLoopFuture<Bool> {
        adapter.addPolicy(sec: sec, ptype: ptype, rule: rule).flatMap { _bool in
            if hasAutoSaveEnable() && !_bool {
               return eventLoopGroup.next().makeSucceededFuture(false)
            }
          let ruleAdded =  model.addPolicy(sec: sec, ptype: ptype, rule: rule)
            let eventData = EventData.AddPolicy(sec, ptype, rule)
           return afterOperatePolicy(sec: sec, oped: ruleAdded, d: eventData, t: ruleAdded)
        }
    }
    
    func addPoliciesInternal(sec:String,ptype:String,rules:[[String]]) -> EventLoopFuture<Bool> {
        adapter.addPolicies(sec: sec, ptype: ptype, rules: rules).flatMap { _bool in
            if hasAutoSaveEnable() && !_bool {
               return eventLoopGroup.next().makeSucceededFuture(false)
            }
            let rulesAdded =  model.addPolicies(sec: sec, ptype: ptype, rules: rules)
            let eventData = EventData.AddPolicies(sec, ptype, rules)
            return afterOperatePolicy(sec: sec, oped: rulesAdded, d: eventData, t: rulesAdded)
        }
    }
    func removePolicyInternal(sec:String,ptype:String,rule:[String]) -> EventLoopFuture<Bool> {
        adapter.removePolicy(sec: sec, ptype: ptype, rule: rule).flatMap { _bool in
            if hasAutoSaveEnable() && !_bool {
               return eventLoopGroup.next().makeSucceededFuture(false)
            }
            let ruleRemoved =  model.removePolicy(sec: sec, ptype: ptype, rule: rule)
            let eventData = EventData.RemovePolicy(sec, ptype, rule)
            return afterOperatePolicy(sec: sec, oped: ruleRemoved, d: eventData, t: ruleRemoved)
        }
    }
    func removePoliciesInternal(sec:String,ptype:String,rules:[[String]]) -> EventLoopFuture<Bool> {
        adapter.removePolicies(sec: sec, ptype: ptype, rules: rules).flatMap { _bool in
            if hasAutoSaveEnable() && !_bool {
               return eventLoopGroup.next().makeSucceededFuture(false)
            }
            let rulesRemoved =  model.removePolicies(sec: sec, ptype: ptype, rules: rules)
            let eventData = EventData.RemovePolicies(sec, ptype, rules)
            
            return afterOperatePolicy(sec: sec, oped: rulesRemoved, d: eventData, t: rulesRemoved)
        }
    }
    func removeFilteredPolicyInternal(sec:String,
                                      ptype:String,
                                      fieldIndex:Int,
                                      fieldValues:[String])
                                        -> EventLoopFuture<(Bool,[[String]])> {
        adapter.removeFilteredPolicy(sec: sec, ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues).flatMap { _bool in
            if hasAutoSaveEnable() && !_bool {
               return eventLoopGroup.next().makeSucceededFuture((false,[]))
            }
            let (rolesRemoved,rules) = model.removeFilteredPolicy(sec: sec, ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues)
            let eventData = EventData.RemoveFilteredPolicy(sec, ptype, rules)
            return afterOperatePolicy(sec: sec, oped: rolesRemoved, d: eventData, t: (rolesRemoved,rules))
        }
    }
    
    
    private func afterOperatePolicy<T: Sendable>(sec:String,oped:Bool,d:EventData,t:T) -> EventLoopFuture<T> {
        if oped {
            emit(e: Event.PolicyChange, d: d)
            emit(e: Event.ClearCache, d: EventData.ClearCache)
        }
        if sec != "g" || !hasAutoBuildRoleLinksEnabled() {
            return eventLoopGroup.next().makeSucceededFuture(t)
        }
        if case let .failure(e) = buildIncrementalRoleLinks(eventData: d) {
            return eventLoopGroup.next().makeFailedFuture(e)
        }
        return eventLoopGroup.next().makeSucceededFuture(t)
    }
}
