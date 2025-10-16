import NIO

// Async/Await overloads for MemoryAdapter
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
extension MemoryAdapter {

    // MARK: Load
    public func loadPolicy(m: Model) async throws {
        for line in policy {
            let sec = line[0]
            let ptype = line[1]
            let rule = Array(line.dropFirst(2))
            if let ast = m.getModel()[sec]?[ptype] {
                ast.policy.append(rule)
            }
        }
    }

    public func loadFilteredPolicy(m: Model, f: Filter) async throws {
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
    }

    // MARK: Save / Clear
    public func savePolicy(m: Model) async throws {
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
    }

    public func clearPolicy() async throws {
        self.policy = []
        self.isFiltered = false
    }

    // MARK: Add
    public func addPolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return self.policy.insert(rule).inserted
    }

    public func addPolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        var allAdded = true
        let rules: [[String]] = rules.map { r in
            var r = r
            r.insert(ptype, at: 0)
            r.insert(sec, at: 0)
            return r
        }
        for rule in rules {
            if policy.contains(rule) {
                allAdded = false
                return allAdded
            }
        }
        self.policy = self.policy.union(rules)
        return allAdded
    }

    // MARK: Remove
    public func removePolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        var rule = rule
        rule.insert(ptype, at: 0)
        rule.insert(sec, at: 0)
        return policy.remove(rule) != nil
    }

    public func removePolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        var allRemoved = true
        let rules: [[String]] = rules.map { r in
            var r = r
            r.insert(ptype, at: 0)
            r.insert(sec, at: 0)
            return r
        }
        // Atomic semantics: if any rule doesn't exist, do not remove any and return false
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
        return allRemoved
    }

    public func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        if fieldValues.isEmpty {
            return false
        }
        var tmp: Set<[String]> = []
        var res = false
        for rule in policy {
            if sec == rule[0] && ptype == rule[1] {
                var matched = true
                for (i, fieldValue) in fieldValues.enumerated() {
                    if !fieldValue.isEmpty && rule[fieldIndex + i + 2] != fieldValue {
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
        return res
    }
}
