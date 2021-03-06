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
            let rule = Array(line[1...])
            if let ast = m.getModel()[sec]?[ptype] {
                ast.policy.append(rule)
            }
        }
        return eventloop.makeSucceededVoidFuture()
    }
    
    public func loadFilteredPolicy(m: Model, f: Filter) -> EventLoopFuture<Void> {
        for line in policy {
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
                self.isFiltered = true
            }
        }
        return eventloop.makeSucceededVoidFuture()
    }
    
    public func savePolicy(m: Model) -> EventLoopFuture<Void> {
        self.policy = []
        if let astMap = m.getModel()["p"] {
            for (ptype,ast) in astMap {
                ptype.forEach { sec in
                    for policy in ast.policy {
                        var rule = policy
                        rule.insert(ptype, at: 0)
                        rule.insert(String(sec), at: 0)
                        self.policy.insert(rule)
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
                        self.policy.insert(rule)
                    }
                }
            }
        }
        return eventloop.makeSucceededVoidFuture()
    }
    
    public func clearPolicy() -> EventLoopFuture<Void> {
        self.policy = []
        self.isFiltered = false
        return eventloop.makeSucceededVoidFuture()
    }
    
    public func addPolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return eventloop.makeSucceededFuture(self.policy.insert(rule).inserted)
        
    }
    
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
    
    public func removePolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return eventloop.makeSucceededFuture(policy.remove(rule) != nil)
    }
    
    public func removePolicies(sec: String, ptype: String, rules: [[String]]) -> EventLoopFuture<Bool> {
        var allRemoved = true
        let  rules:[[String]] = rules.map { rule in
            var rule = rule
            rule.insert(ptype, at: 0)
            rule.insert(sec, at: 0)
            return rule
        }
        for rule in rules {
            if policy.contains(rule) {
                allRemoved = false
                return eventloop.makeSucceededFuture(allRemoved)
            }
        }
        for rule in rules {
            self.policy.remove(rule)
        }
        return eventloop.makeSucceededFuture(allRemoved)
    }
    
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
    
    
}
