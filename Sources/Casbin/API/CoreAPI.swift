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

import Logging

public protocol CoreAPI: EventEmitter where K == Event {
    func addFunction(fname: String, f: @escaping ExpressionFunction)
    var model: Model {get}
    var adapter: Adapter {get}
    var watcher: Watcher? {get set}

    func getRoleManager() -> RoleManager

    func setRoleManager(rm: RoleManager) -> CasbinResult<Void>

    var logger: Logger {get set}

    func setModel(_ model: Model) async throws

    func setAdapter(_ adapter: Adapter) async throws

    func enforce(rvals: [Any]) -> Result<Bool,Error>

    func buildRoleLinks() -> CasbinResult<Void>

    func buildIncrementalRoleLinks(eventData: EventData) -> CasbinResult<Void>

    func loadPolicy() async throws
    func loadFilterdPolicy(_ f: Filter) async throws

    var isFiltered: Bool {get}
    var isEnabled: Bool { get }
    var enableLog: Bool {get set}

    func savePolicy() async throws
    func clearPolicy() async throws

    func enableAutoSave(auto: Bool)
    func enableEnforce(enabled: Bool)
    func enableAutoBuildRoleLinks(auto: Bool)
    func enableAutoNotifyWatcher(auto: Bool)

    func hasAutoSaveEnable() -> Bool
    func hasAutoNotifyWatcherEnabled() -> Bool

    func hasAutoBuildRoleLinksEnabled() -> Bool

    func getCache() -> Cache?
    func setCapacity(_ c: Int)
}





