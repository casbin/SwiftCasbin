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

extension CoreAPI {
    //MARK: InternalApi
    func addPolicyInternal(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        let _bool = try await adapter.addPolicy(sec: sec, ptype: ptype, rule: rule)
        if hasAutoSaveEnable() && !_bool {
            return false
        }
        let ruleAdded = model.addPolicy(sec: sec, ptype: ptype, rule: rule)
        let eventData = EventData.AddPolicy(sec, ptype, rule)
        return try afterOperatePolicy(sec: sec, oped: ruleAdded, d: eventData, t: ruleAdded)
    }

    func addPoliciesInternal(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        let _bool = try await adapter.addPolicies(sec: sec, ptype: ptype, rules: rules)
        if hasAutoSaveEnable() && !_bool {
            return false
        }
        let rulesAdded = model.addPolicies(sec: sec, ptype: ptype, rules: rules)
        let eventData = EventData.AddPolicies(sec, ptype, rules)
        return try afterOperatePolicy(sec: sec, oped: rulesAdded, d: eventData, t: rulesAdded)
    }

    func removePolicyInternal(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        let _bool = try await adapter.removePolicy(sec: sec, ptype: ptype, rule: rule)
        if hasAutoSaveEnable() && !_bool {
            return false
        }
        let ruleRemoved = model.removePolicy(sec: sec, ptype: ptype, rule: rule)
        let eventData = EventData.RemovePolicy(sec, ptype, rule)
        return try afterOperatePolicy(sec: sec, oped: ruleRemoved, d: eventData, t: ruleRemoved)
    }

    func removePoliciesInternal(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        let _bool = try await adapter.removePolicies(sec: sec, ptype: ptype, rules: rules)
        if hasAutoSaveEnable() && !_bool {
            return false
        }
        let rulesRemoved = model.removePolicies(sec: sec, ptype: ptype, rules: rules)
        let eventData = EventData.RemovePolicies(sec, ptype, rules)
        return try afterOperatePolicy(sec: sec, oped: rulesRemoved, d: eventData, t: rulesRemoved)
    }

    func removeFilteredPolicyInternal(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> (Bool,[[String]]) {
        let _bool = try await adapter.removeFilteredPolicy(sec: sec, ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues)
        if hasAutoSaveEnable() && !_bool {
            return (false, [])
        }
        let (rolesRemoved, rules) = model.removeFilteredPolicy(sec: sec, ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues)
        let eventData = EventData.RemoveFilteredPolicy(sec, ptype, rules)
        return try afterOperatePolicy(sec: sec, oped: rolesRemoved, d: eventData, t: (rolesRemoved, rules))
    }

    private func afterOperatePolicy<T>(sec: String, oped: Bool, d: EventData, t: T) throws -> T {
        if oped {
            emit(e: Event.PolicyChange, d: d)
            emit(e: Event.ClearCache, d: EventData.ClearCache)
        }
        if sec != "g" || !hasAutoBuildRoleLinksEnabled() {
            return t
        }
        try buildIncrementalRoleLinks(eventData: d).get()
        return t
    }
}

