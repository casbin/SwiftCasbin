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

public final class MemoryAdapter: Sendable {
    public init() {
    }

    private let policy: Mutex<Set<[String]>> = Mutex(Set<[String]>())
    private let filtered: Mutex<Bool> = Mutex(false)

    public var isFiltered: Bool {
        filtered.withLock { $0 }
    }
}

extension MemoryAdapter: Adapter {
    public func loadPolicy(m: Model) async throws {
        policy.withLock { policySet in
            for line in policySet {
                let sec = line[0]
                let ptype = line[1]
                let rule = Array(line[1...])
                if let ast = m.getModel()[sec]?[ptype] {
                    ast.policy.append(rule)
                }
            }
        }
    }

    public func loadFilteredPolicy(m: Model, f: Filter) async throws {
        policy.withLock { policySet in
            for line in policySet {
                let sec = line[0]
                let ptype = line[1]
                let rule = Array(line[1...])
                var isFiltered = false
                if sec == "p" {
                    for (i,r) in f.p.enumerated() {
                        if !r.isEmpty && r != rule[i+1] {
                            isFiltered = true
                        }
                    }
                }
                if sec == "g" {
                    for (i,r) in f.g.enumerated() {
                        if !r.isEmpty && r != rule[i+1] {
                            isFiltered = true
                        }
                    }
                }
                if !isFiltered {
                    if let ast = m.getModel()[sec]?[ptype] {
                        ast.policy.append(rule)
                    }
                } else {
                    filtered.withLock { $0 = true }
                }
            }
        }
    }

    public func savePolicy(m: Model) async throws {
        policy.withLock { policySet in
            policySet = []
            if let astMap = m.getModel()["p"] {
                for (ptype,ast) in astMap {
                    ptype.forEach { sec in
                        for policy in ast.policy {
                            var rule = policy
                            rule.insert(ptype, at: 0)
                            rule.insert(String(sec), at: 0)
                            policySet.insert(rule)
                        }
                    }
                }
            }
            if let astMap = m.getModel()["g"] {
                for (ptype,ast) in astMap {
                    ptype.forEach { sec in
                        for policy in ast.policy {
                            var rule = policy
                            rule.insert(ptype, at: 0)
                            rule.insert(String(sec), at: 0)
                            policySet.insert(rule)
                        }
                    }
                }
            }
        }
    }

    public func clearPolicy() async throws {
        policy.withLock { $0 = [] }
        filtered.withLock { $0 = false }
    }

    public func addPolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return policy.withLock { $0.insert(rule).inserted }
    }

    public func addPolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        return policy.withLock { policySet in
            var allAdded = true
            let rules:[[String]] = rules.map { rule in
                var rule = rule
                rule.insert(ptype, at: 0)
                rule.insert(sec, at: 0)
                return rule
            }
            for rule in rules {
                if policySet.contains(rule) {
                    allAdded = false
                    return allAdded
                }
            }
            policySet = policySet.union(rules)
            return allAdded
        }
    }

    public func removePolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return policy.withLock { $0.remove(rule) != nil }
    }

    public func removePolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        return policy.withLock { policySet in
            var allRemoved = true
            let rules:[[String]] = rules.map { rule in
                var rule = rule
                rule.insert(ptype, at: 0)
                rule.insert(sec, at: 0)
                return rule
            }
            for rule in rules {
                if policySet.contains(rule) {
                    allRemoved = false
                    return allRemoved
                }
            }
            for rule in rules {
                policySet.remove(rule)
            }
            return allRemoved
        }
    }

    public func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        if fieldValues.isEmpty {
            return false
        }
        return policy.withLock { policySet in
            var tmp:Set<[String]> = []
            var res = false
            for rule in policySet {
                if sec == rule[0] && ptype == rule [1] {
                    var matched = true
                    for (i,fieldValue) in fieldValues.enumerated() {
                        if !fieldValue.isEmpty
                            && rule[fieldIndex + i + 2] != fieldValue {
                            matched = false
                            break
                        }
                    }
                    if matched {
                        res = true
                    } else {
                        tmp.insert(rule)
                    }
                } else {
                    tmp.insert(rule)
                }
            }
            policySet = tmp
            return res
        }
    }
}
