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
public struct NullAdapter: Adapter {
    public var isFiltered: Bool {
        return true
    }
    
    init(eventloop: EventLoop) {
        self.eventloop = eventloop
    }
    
    public var eventloop: EventLoop
    
    public func loadPolicy(m: Model) -> EventLoopFuture<Void> {
        eventloop.makeSucceededVoidFuture()
    }
    
    public func loadFilteredPolicy(m: Model, f: Filter) -> EventLoopFuture<Void> {
        eventloop.makeSucceededVoidFuture()
    }
    
    public func savePolicy(m: Model) -> EventLoopFuture<Void> {
        eventloop.makeSucceededVoidFuture()
    }
    
    public func clearPolicy() -> EventLoopFuture<Void> {
        eventloop.makeSucceededVoidFuture()
    }
    
   
    
    public func addPolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        eventloop.makeSucceededFuture(true)
    }
    
    public func addPolicies(sec: String, ptype: String, rules: [[String]]) -> EventLoopFuture<Bool> {
        eventloop.makeSucceededFuture(true)
    }
    
    public func removePolicy(sec: String, ptype: String, rule: [String]) -> EventLoopFuture<Bool> {
        eventloop.makeSucceededFuture(true)
    }
    
    public func removePolicies(sec: String, ptype: String, rules: [[String]]) -> EventLoopFuture<Bool> {
        eventloop.makeSucceededFuture(true)
    }
    
    public func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) -> EventLoopFuture<Bool> {
        eventloop.makeSucceededFuture(true)
    }
    
}
