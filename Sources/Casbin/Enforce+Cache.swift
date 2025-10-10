//
//  Enforce+Cache.swift
//  Casbin
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

extension Enforcer {
    // Enable in-memory LRU cache for enforce results
    /// Enables an in-memory LRU cache for enforce results.
    /// - Parameter capacity: Maximum number of entries to store.
    public func enableMemoryCache(capacity: Int = 200) {
        let lru = LruCache<Int,Bool>(capacity: capacity)
        self.cache = DefaultCache(lru: lru)
    }

    // Internal helper used by enforce to consult/update cache
    func cachedPrivateEnforce(rvals:[any Sendable],cacheKey:Int) -> Result<(Bool,Bool,[Int]?),Error> {
        if let authorized = self.cache?.get(key: cacheKey, as: Bool.self) {
            return .success((authorized, true, nil))
        } else {
            return self.privateEnforce(rvals: rvals).map { (authorized, indices) in
                self.cache?.set(key: cacheKey, value: authorized)
                return (authorized,false,indices)
            }
        }
    }
}
