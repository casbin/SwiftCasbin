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

import NIOConcurrencyHelpers

/// A simple in-memory LRU-backed cache used by the Enforcer.
/// - Note: Thread-safety is provided by the underlying LruCache.
public final class DefaultCache: Cache {
    init(lru: LruCache<Int, Bool>) {
        self.lru = lru
    }
    
    public func get<K, V>(key: K, as type: V.Type) -> V? where K : Hashable {
        (lru.getValue(forKey:key as! Int) as! V)
    }
    
    public func set<K, V>(key: K, value: V) where K : Hashable {
        lru.setValue(value: value as! Bool, forKey: key as! Int)
    }
    
    public func has<K>(k: K) -> Bool where K : Hashable {
        get(key: k, as: Bool.self) != nil
    }
    
    public func clear() {
        lru.clear()
    }
    
    var lru: LruCache<Int,Bool>
    public func setCapacity(_ c: Int) {
        lru.capacity = c
    }
}

/// A minimal O(1) LRU cache using a dictionary + doubly linked list.
/// Operations are protected by a `NIOLock` and are safe for concurrent use.
final class LruCache<Key: Hashable, Value> {
    private class ListNode {
            var key: Key?
            var value: Value?
            var prevNode: ListNode?
            var nextNode: ListNode?
            
            init(key: Key? = nil, value: Value? = nil) {
                self.key = key
                self.value = value
            }
        }
    private var storage: [Key: ListNode] = [:]
    /// Maximum number of entries. When full, the least-recently-used entry is evicted.
    var capacity = 0
    private var lock: NIOLock
    
    /// head's nextNode is the actual first node in the Double Linked-list.
    private var head = ListNode()
    /// tail's prevNode is the actual last node in the Double Linked-list.
    private var tail = ListNode()
    
    init(capacity: Int) {
        self.capacity = capacity
        head.nextNode = tail
        tail.prevNode = head
        self.lock = .init()
    }
    /// Remove a node from the linked list and storage. Caller must hold the lock.
    private func removeUnlocked(_ node: ListNode) {
        node.prevNode?.nextNode = node.nextNode
        node.nextNode?.prevNode = node.prevNode
        if let key = node.key { storage.removeValue(forKey: key) }
    }
    func clear() {
        self.lock.lock()
        defer { self.lock.unlock() }
        self.storage = [:]
    }
    /// Insert a node at the head (most recently used). Caller must hold the lock.
    private func insertToHeadUnlocked(_ node: ListNode) {
        head.nextNode?.prevNode = node
        node.nextNode = head.nextNode
        node.prevNode = head
        head.nextNode = node
        if let key = node.key { storage[key] = node }
    }
    /// When the cache hit happen, remove the node what you get and insert to Head side again.
    func getValue(forKey key: Key) -> Value? {
        self.lock.lock()
        defer { self.lock.unlock() }
        guard let node = storage[key] else { return nil }
        removeUnlocked(node)
        insertToHeadUnlocked(node)
        return node.value
    }
    /// Push your value and if there is same value, remove that automatically.
        /// if not, remove Least Recently Used Node and push new node.
    func setValue(value: Value, forKey key: Key) {
        self.lock.lock()
        defer { self.lock.unlock() }
        // Update existing
        if let existing = storage[key] {
            existing.value = value
            removeUnlocked(existing)
            insertToHeadUnlocked(existing)
            return
        }
        // Capacity guard
        guard capacity > 0 else { return }
        // Evict if full
        if storage.count >= capacity, let last = tail.prevNode, last !== head {
            removeUnlocked(last)
        }
        let newNode = ListNode(key: key, value: value)
        insertToHeadUnlocked(newNode)
    }
}
