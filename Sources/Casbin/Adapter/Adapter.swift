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

/// Filter used for loading a subset of the policy from an adapter.
public struct Filter: Sendable {
    public init(p: [String], g: [String]) {
        self.p = p
        self.g = g
    }

    public let p: [String]
    public let g: [String]
}

/// Adapters load and persist policy for an ``Enforcer``.
public protocol Adapter: Sendable {
    func loadPolicy(m: Model) async throws

    func loadFilteredPolicy(m: Model, f: Filter) async throws

    func savePolicy(m: Model) async throws
    func clearPolicy() async throws

    var isFiltered: Bool {get}

    func addPolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool

    func addPolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool

    func removePolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool

    func removePolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool

    func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> Bool
}
