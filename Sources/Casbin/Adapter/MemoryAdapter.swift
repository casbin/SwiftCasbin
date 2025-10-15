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

public final class MemoryAdapter {
    public init(on eventloop: EventLoop) {
        self.eventloop = eventloop
    }

    var policy:Set<[String]> = []
    public var isFiltered: Bool = false
    public var eventloop: EventLoop
}

extension MemoryAdapter: Adapter {


    public func loadPolicy(m: Model) -> EventLoopFuture<Void> {
        for line in policy {
            let sec = line[0]
            let ptype = line[1]
            // Model policies should NOT include ptype; drop sec and ptype headers
            let rule = Array(line.dropFirst(2))
            if let ast = m.getModel()[sec]?[ptype] {
                ast.policy.append(rule)
            }
        }
        return eventloop.makeSucceededVoidFuture()
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func loadFilteredPolicy(m: Model, f: Filter) -> EventLoopFuture<Void> {
        for line in policy {
            let sec = line[0]
            let ptype = line[1]
            let rule = Array(line.dropFirst(2))
            var isFiltered = false
            if sec == "p" {
                for (i,r) in f.p.enumerated() {
                    if !r.isEmpty && r != rule[i] {
                        isFiltered = true
                    }
                }
            }
            if sec == "g" {
                for (i,r) in f.g.enumerated() {
                    if !r.isEmpty && r != rule[i] {
                        isFiltered = true
                    }
                }
            }
            if !isFiltered {
                if let ast = m.getModel()[sec]?[ptype] {
                    ast.policy.append(rule)
                }
            } else {
                self.isFiltered = true
            }
        }
        return eventloop.makeSucceededVoidFuture()
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func savePolicy(m: Model) -> EventLoopFuture<Void> {
        self.policy = []
        if let astMap = m.getModel()["p"] {
            for (ptype,ast) in astMap {
                for policy in ast.policy {
                    var rule = policy
                    rule.insert(ptype, at: 0)
                    rule.insert("p", at: 0)
                    self.policy.insert(rule)
                }
            }
        }
        if let astMap = m.getModel()["g"] {
            for (ptype,ast) in astMap {
                for policy in ast.policy {
                    var rule = policy
                    rule.insert(ptype, at: 0)
                    rule.insert("g", at: 0)
                    self.policy.insert(rule)
                }
            }
        }
        return eventloop.makeSucceededVoidFuture()
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func clearPolicy() -> EventLoopFuture<Void> {
        self.policy = []
        self.isFiltered = false
        return eventloop.makeSucceededVoidFuture()
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func addPolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return eventloop.makeSucceededFuture(self.policy.insert(rule).inserted)
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func addPolicies(sec: String, ptype: String, rules: [[String]]) -> EventLoopFuture<Bool> {
        var allAdded = true
        let rules:[[String]] = rules.map { rule in
            var rule = rule
            rule.insert(ptype, at: 0)
            rule.insert(sec, at: 0)
            return rule
        }
        for rule in rules {
            if policy.contains(rule) {
                allAdded = false
                return eventloop.makeSucceededFuture(allAdded)
            }
        }
        self.policy = self.policy.union(rules)
        return eventloop.makeSucceededFuture(allAdded)
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func removePolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return eventloop.makeSucceededFuture(policy.remove(rule) != nil)
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func removePolicies(sec: String, ptype: String, rules: [[String]]) -> EventLoopFuture<Bool> {
        var allRemoved = true
        let  rules:[[String]] = rules.map { rule in
            var rule = rule
            rule.insert(ptype, at: 0)
            rule.insert(sec, at: 0)
            return rule
        }
        // Atomic semantics: if any rule doesn't exist, do not remove any and return false.
        for rule in rules {
            if !policy.contains(rule) {
                allRemoved = false
                break
            }
        }
        if allRemoved {
            for rule in rules {
                _ = self.policy.remove(rule)
            }
        }
        return eventloop.makeSucceededFuture(allRemoved)
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift

    public func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) -> EventLoopFuture<Bool> {
        if fieldValues.isEmpty {
            return eventloop.makeSucceededFuture(false)
        }
        var tmp:Set<[String]> = []
        var res = false
        for rule in policy {
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
        self.policy = tmp
        return eventloop.makeSucceededFuture(res)
    }

    // Async/await overloads moved to MemoryAdapter+AsyncAwait.swift
}
