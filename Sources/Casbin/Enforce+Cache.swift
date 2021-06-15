//
//  Enforce+Cache.swift
//  Casbin
//
//

import Foundation
import NIO
/// Custom cache
/// ```
/// extension Application.Caches.Provider {
///   public static var memory: Self {
///      .init {
///            $0.caches.use { $0.caches.memory }
///      }
///  }
/// e.caches.use(.memory)
extension Enforcer {
    
    public var caches: Caches {
        .init(enforcer: self)
    }
    public struct Caches {
        public let enforcer: Enforcer
        
        public struct Provider {
            let run: (Enforcer) -> ()
            
            public init(_ run: @escaping (Enforcer) -> ()) {
                self.run = run
            }
            public static var memory:Self {
                .init {
                    $0.caches.use {
                        $0.caches.memory
                    }
                }
            }
        }
        public func use(_ provider: Provider) {
            provider.run(self.enforcer)
        }
        private struct CacheKey: StorageKey {
            typealias Value = CacheStorage
        }
        final class CacheStorage {
            var makeCache:((Enforcer) -> Cache)?
            init() {}
        }
        var cacheStorage: CacheStorage {
            guard let storage = self.enforcer.storage[CacheKey.self] else {
                let storage = CacheStorage.init()
                self.enforcer.storage[CacheKey.self] = storage
                return storage
            }
            return storage
        }
        public func use(_ makeCache: @escaping (Enforcer) -> Cache) {
            self.cacheStorage.makeCache = makeCache
        }
        
        public var memory: Cache {
            DefaultCache.init(lru: memoryStorage)
        }
        private var memoryStorage: LruCache<Int,Bool> {
            let lock = self.enforcer.locks.lock(for: MemoryCacheKey.self)
            lock.lock()
            defer { lock.unlock() }
            if let existing = self.enforcer.storage.get(MemoryCacheKey.self) {
                return existing
            } else {
                let new = LruCache<Int,Bool>.init(capacity: 200)
                self.enforcer.storage.set(MemoryCacheKey.self, to: new)
                return new
            }
        }
        private struct MemoryCacheKey: LockKey,StorageKey {
            typealias Value = LruCache<Int,Bool>
        }
    }
    public var cache: Cache? {
        get {
            guard let makeCache = self.caches.cacheStorage.makeCache else {
                return nil
            }
            return makeCache(self)
        }
        set { }
    }
}

extension Enforcer {
    func cachedPrivateEnforce(rvals:[Any],cacheKey:Int) -> Result<(Bool,Bool,[Int]?),Error> {
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
