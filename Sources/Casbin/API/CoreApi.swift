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
import Logging

public protocol CoreApi:EventEmitter where K == Event {
    func addFunction(fname:String,f:@escaping ExpressionFunction)
    var eventLoopGroup: EventLoopGroup {get}
    var model: Model {get}
    var adapter: Adapter {get}
    var watcher: Watcher? {get set}
    
    func getRoleManager() -> RoleManager
    
    func setRoleManager(rm:RoleManager) -> CasbinResult<Void>
    
    var logger: Logger {get set}
    
    func setModel(_ model: Model) -> EventLoopFuture<Void>
    
    func setAdapter(_ adapter: Adapter) -> EventLoopFuture<Void>
    
    func enforce(rvals:[Any]) -> Result<Bool,Error>
    
    func buildRoleLinks() -> CasbinResult<Void>
    
    func buildIncrementalRoleLinks(eventData:EventData) ->  CasbinResult<Void>
    
    func loadPolicy() -> EventLoopFuture<Void>
    func loadFilterdPolicy(_ f:Filter) -> EventLoopFuture<Void>
    
    var isFiltered: Bool {get}
    var isEnabled: Bool { get }
    var  enableLog:Bool {get set}
    
    func savePolicy() -> EventLoopFuture<Void>
    func clearPolicy() -> EventLoopFuture<Void>
    
    func enableAutoSave(auto:Bool)
    func enableEnforce(enabled:Bool)
    func enableAutoBuildRoleLinks(auto: Bool)
    func enableAutoNotifyWatcher(auto: Bool)
    
    func hasAutoSaveEnable() -> Bool
    func hasAutoNotifyWatcherEnabled() -> Bool
    
    func hasAutoBuildRoleLinksEnabled() -> Bool
    
    func getCache() -> Cache?
    func setCapacity(_ c: Int)
}





