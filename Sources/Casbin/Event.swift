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

public enum Event:EventKey {
    case PolicyChange
    case ClearCache
}

public enum EventData: CustomStringConvertible {
    public var description: String {
        switch self {
       
        case .AddPolicy(let sec, let ptype, let p):
            return "Type: AddPolicy, Assertion:\(sec)::\(ptype),Data:\(p.joined(separator: ","))"
        case .AddPolicies(let sec, let ptype, let p):
            return "Type: AddPolicies, Assertion:\(sec)::\(ptype),Added:\(p.count)"
        case .RemovePolicy(let sec, let ptype, let p):
            return "Type: RemovePolicy, Assertion:\(sec)::\(ptype),Data:\(p.joined(separator: ","))"
        case .RemovePolicies(let sec, let ptype, let p):
            return "Type: RemovePolicies, Assertion:\(sec)::\(ptype),Removed:\(p.count)"
        case .RemoveFilteredPolicy(let sec, let ptype, let p):
            return "Type: RemoveFilteredPolicy, Assertion:\(sec)::\(ptype),Removed:\(p.count)"
        case .SavePolicy(let p):
            return "Type: SavePolicy, Saved: \(p.count)"
        case .ClearPolicy:
            return "Type: ClearPolicy"
        case .ClearCache:
            return "Type: ClearCache"
        }
    }
    
    case AddPolicy(String,String,[String])
    case AddPolicies(String,String,[[String]])
    case RemovePolicy(String,String,[String])
    case RemovePolicies(String,String,[[String]])
    case RemoveFilteredPolicy(String,String,[[String]])
    case SavePolicy([[String]])
    case ClearPolicy
    case ClearCache
}
public protocol EventKey:Hashable & Equatable {}

public protocol EventEmitter {
    associatedtype K:EventKey
    func on(e:K,f:@escaping (EventData,Self) -> Void)
    func off(e:K)
    func emit(e:K,d:EventData)
}

func notifyLoggerAndWatcher<T:CoreApi>(eventData:EventData,e: T) {
    if e.enableLog {
        e.logger.printMgmtLog(e: eventData, level: e.logger.logLevel)
    }
    if let w = e.watcher {
        w.update(eventData: eventData)
    }
}
func clearCache<T:CoreApi>(eventData:EventData,e: T) {
    e.logger.printMgmtLog(e: eventData)
    e.getCache()?.clear()
}
