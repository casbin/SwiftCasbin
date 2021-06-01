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

public struct Filter {
    public let p: [String]
    public let g: [String]
}

public protocol Adapter {
    var eventloop: EventLoop {get}
    
    func loadPolicy(m:Model) -> EventLoopFuture<Void>
    
    func loadFilteredPolicy(m:Model,f:Filter) -> EventLoopFuture<Void>
    
    func savePolicy(m: Model) -> EventLoopFuture<Void>
    func clearPolicy() -> EventLoopFuture<Void>
    
    var isFiltered: Bool {get}
    
    func addPolicy(sec:String,ptype:String,rule:[String]) -> EventLoopFuture<Bool>
    
    func addPolicies(sec:String,ptype:String,rules:[[String]]) -> EventLoopFuture<Bool>
    
    func removePolicy(sec:String,ptype:String,rule:[String]) -> EventLoopFuture<Bool>
    
    func removePolicies(sec:String,ptype:String,rules:[[String]]) -> EventLoopFuture<Bool>
    
    func removeFilteredPolicy(sec:String,ptype:String,fieldIndex:Int,fieldValues:[String]) -> EventLoopFuture<Bool>
}
