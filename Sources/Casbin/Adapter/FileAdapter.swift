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

import Foundation

public typealias LoadPolicyFileHandler = @Sendable (String, Model) -> Void
public typealias LoadFilteredPolicyFileHandler = @Sendable (String, Model, Filter) -> Bool

public final class FileAdapter: Sendable {
    private let filePath: String
    private let filtered: Mutex<Bool> = Mutex(false)

    public var isFiltered: Bool {
        filtered.withLock { $0 }
    }

    public init(filePath: String) {
        self.filePath = filePath
    }

    private func load() async throws -> String {
        let url = URL(fileURLWithPath: filePath)
        let data = try Data(contentsOf: url)
        guard let content = String(data: data, encoding: .utf8) else {
            throw CasbinError.IoError("Failed to decode file content as UTF-8")
        }
        return content
    }

    private func loadPolicyFile(m: Model, handler: @escaping LoadPolicyFileHandler) async throws {
        let content = try await load()
        let lines = content.split(separator: "\n")
        lines.forEach {
            handler(String($0), m)
        }
    }

    private func loadFilteredPolicyFile(m: Model, filter: Filter, handler: @escaping LoadFilteredPolicyFileHandler) async throws -> Bool {
        let content = try await load()
        let lines = content.split(separator: "\n")
        var isFiltered = false
        for line in lines {
            if handler(String(line), m, filter) {
                isFiltered = true
            }
        }
        return isFiltered
    }

    private func savePolicyFile(text: String) async throws {
        let url = URL(fileURLWithPath: filePath)
        guard let data = text.data(using: .utf8) else {
            throw CasbinError.IoError("Failed to encode text as UTF-8")
        }
        try data.write(to: url, options: .atomic)
    }
}

extension FileAdapter: Adapter {
    public func loadPolicy(m: Model) async throws {
        try await loadPolicyFile(m: m, handler: Util.loadPolicyLine(line:m:))
    }

    public func loadFilteredPolicy(m: Model, f: Filter) async throws {
        let isFiltered = try await loadFilteredPolicyFile(m: m, filter: f, handler: Util.loadFilteredPolicyLine)
        filtered.withLock { $0 = isFiltered }
    }

    public func savePolicy(m: Model) async throws {
        if filePath.isEmpty {
            throw CasbinError.IoError("save policy failed, file path is empty")
        }
        var policies = ""
        guard let astMap = m.getModel()["p"] else {
            throw CasbinError.MODEL_ERROR(.P("Missing policy definition in conf file"))
        }
        for (ptype,ast) in astMap {
            for rule in ast.policy {
                policies.append("\(ptype),\(rule.joined(separator: ","))\n")
            }
        }
        if let asts =  m.getModel()["g"] {
            for (ptype,ast) in asts {
                for rule in ast.policy {
                    policies.append("\(ptype),\(rule.joined(separator: ","))\n")
                }
            }
        }
        try await savePolicyFile(text: policies)
    }

    public func clearPolicy() async throws {
        try await savePolicyFile(text: "")
    }

    public func addPolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        // this api shouldn't implement, just for convenience
        return true
    }

    public func addPolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        // this api shouldn't implement, just for convenience
        return true
    }

    public func removePolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        // this api shouldn't implement, just for convenience
        return true
    }

    public func removePolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        // this api shouldn't implement, just for convenience
        return true
    }

    public func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        // this api shouldn't implement, just for convenience
        return true
    }
}
