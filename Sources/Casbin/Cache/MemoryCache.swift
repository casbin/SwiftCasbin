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

/// A thread-safe default in-memory cache backed by a lock-protected LRU.
///
/// - Note: Keys and values must be `Sendable`. This cache is intended for
///         use inside `Enforcer` and is not marked `Sendable` itself since
///         the actor boundary provides isolation.
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

    let lru: LruCache<Int,Bool>
    public func setCapacity(_ c: Int) {
        lru.capacity = c
    }
}

/// A simple thread-safe LRU cache with O(1) get/set operations.
///
/// Implementation details:
/// - Uses a doubly-linked list of Nodes for recency ordering and a Dictionary
///   for key lookups.
/// - Synchronization is provided by a `Mutex` — callers must not assume
///   re-entrant callbacks from within cache operations.
/// - Sentinels `head` and `tail` have `nil` key/value and are not observable.
///
/// Complexity:
/// - `getValue(forKey:)` — O(1)
/// - `setValue(value:forKey:)` — O(1)
final class LruCache<Key: Hashable & Sendable, Value: Sendable> {
    private final class Node {
        var key: Key?
        var value: Value?
        var prev: Node?
        var next: Node?
        init(key: Key? = nil, value: Value? = nil) { self.key = key; self.value = value }
    }

    private struct State {
        var dict: [Key: Node]
        var head: Node
        var tail: Node
    }
    private let state: Mutex<State>
    var capacity: Int

    /// Create an LRU with a maximum number of entries.
    /// - Parameter capacity: Maximum items to retain. On insert beyond
    ///   capacity, the least-recently-used item is evicted.
    init(capacity: Int) {
        self.capacity = capacity
        let head = Node()
        let tail = Node()
        head.next = tail
        tail.prev = head
        self.state = Mutex(State(dict: [:], head: head, tail: tail))
    }

    /// Remove all entries.
    func clear() {
        state.withLock { st in
            st.dict.removeAll(keepingCapacity: false)
            st.head.next = st.tail
            st.tail.prev = st.head
        }
    }

    // helpers are written inline inside withLock to avoid task isolation issues

    /// Returns a value for `key` and promotes the entry to most-recently-used.
    func getValue(forKey key: Key) -> Value? {
        var out: Value?
        state.withLock { st in
            guard let node = st.dict[key] else { return }
            // detach
            node.prev?.next = node.next
            node.next?.prev = node.prev
            // attach to front
            node.next = st.head.next
            node.prev = st.head
            st.head.next?.prev = node
            st.head.next = node
            out = node.value
        }
        return out
    }

    /// Inserts or updates `key` with `value` and promotes it to most-recently-used.
    func setValue(value: Value, forKey key: Key) {
        state.withLock { st in
            if let node = st.dict[key] {
                node.value = value
                // detach
                node.prev?.next = node.next
                node.next?.prev = node.prev
                // attach to front
                node.next = st.head.next
                node.prev = st.head
                st.head.next?.prev = node
                st.head.next = node
                return
            }
            let node = Node(key: key, value: value)
            st.dict[key] = node
            // attach to front
            node.next = st.head.next
            node.prev = st.head
            st.head.next?.prev = node
            st.head.next = node
            if st.dict.count > capacity, let lru = st.tail.prev, lru !== st.head, let k = lru.key {
                // detach LRU
                lru.prev?.next = lru.next
                lru.next?.prev = lru.prev
                st.dict.removeValue(forKey: k)
            }
        }
    }
}
