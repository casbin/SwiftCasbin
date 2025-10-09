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
import Synchronization
extension Enforcer {
    internal var core: Core {
        .init(ef: self)
    }
    public var watcher: Watcher? {
        get {
//            guard let watcher = self.core.storage.watcher else {
//                fatalError("watcher not configured. Configure with ef.watcher = xxx")
//            }
            return self.core.storage.watcher
        }
        set {
            self.core.storage.watcher = newValue
        }
    }
    var fm: FunctionMap {
        get {self.core.storage.fm}
        set {self.core.storage.fm = newValue}
    }
    public var roleManager: RoleManager {
        get {self.core.storage.rm}
        set {
            self.core.storage.rm = newValue
        }
    }
    public var eft: Effector {
        get {self.core.storage.eft}
        set {self.core.storage.eft = newValue}
    }
    
    public func withSync<R>(_ body: @Sendable (inout sending ()) throws -> sending R) rethrows -> R {
        try self.core.storage.locks.main.withLock(body)
    }
    
    public struct Core {
        final class Storage {
           
            var eft: Effector
            var watcher:Watcher?
            var rm: RoleManager
            var fm: FunctionMap
            var locks: Locks
            init() {
                self.eft = DefaultEffector.init()
                self.rm = DefaultRoleManager.init(maxHierarchyLevel: 10)
                self.fm = FunctionMap.default()  
                self.watcher = nil
                self.locks = .init()
            }
            
        }
        let ef: Enforcer
        
        struct Key:StorageKey {
            typealias Value = Storage
        }
        
        var storage: Storage {
            guard let storage = self.ef.storage[Key.self] else {
                fatalError("Core not configured. Configure with ef.core.initialize()")
            }
            return storage
        }
        func initialize() {
            self.ef.storage[Key.self] = .init()
        }
    }
    
    public struct Locks: ~Copyable {
        public let main: Mutex<()>

        init() {
            self.main = Mutex(())
        }
    }
}


public protocol LockKey { }
