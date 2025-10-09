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

public final class DefaultCache: Cache, Sendable {
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

final class LruCache<Key:Hashable,Value>: @unchecked Sendable {
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

    private struct State {
        var storage: [Key:ListNode] = [:]
        var head: ListNode
        var tail: ListNode

        init(head: ListNode, tail: ListNode) {
            self.head = head
            self.tail = tail
        }
    }

    var capacity = 0
    private let state: Mutex<State>

    init(capacity: Int) {
        self.capacity = capacity
        let head = ListNode()
        let tail = ListNode()
        head.nextNode = tail
        tail.prevNode = head
        self.state = Mutex(State(head: head, tail: tail))
    }
    /// Remove Node in the Double Linked-list.
    private func remove(node: ListNode, state: inout State) {
        node.prevNode?.nextNode = node.nextNode
        node.nextNode?.prevNode = node.prevNode
        guard let key = node.key else { return }
        state.storage.removeValue(forKey: key)
    }

    func clear() {
        state.withLock { $0.storage = [:] }
    }

    /// insertion is always fullfilled on the Head side.
    private func insertToHead(node: ListNode, state: inout State) {
        state.head.nextNode?.prevNode = node
        node.nextNode = state.head.nextNode
        node.prevNode = state.head
        state.head.nextNode = node
        guard let key = node.key else { return }
        state.storage.updateValue(node, forKey: key)
    }

    /// When the cache hit happen, remove the node what you get and insert to Head side again.
    func getValue(forKey key: Key) -> Value? {
        state.withLock { state in
            if !state.storage.contains(where: { $0.key == key }) {
                return nil
            }
            guard let node = state.storage[key] else { return nil }
            remove(node: node, state: &state)
            insertToHead(node: node, state: &state)
            return node.value
        }
    }

    /// Push your value and if there is same value, remove that automatically.
    /// if not, remove Least Recently Used Node and push new node.
    func setValue(value: Value, forKey key: Key) {
        state.withLock { state in
            let newNode = ListNode(key: key, value: value)
            if state.storage.contains(where: { $0.key == key }){
                guard let oldNode = state.storage[key] else { return }
                remove(node: oldNode, state: &state)
            } else {
                if state.storage.count >= capacity {
                    guard let tailNode = state.tail.prevNode else { return }
                    remove(node: tailNode, state: &state) // remove Least Recently Used Node
                }
            }
            insertToHead(node: newNode, state: &state)
        }
    }
}
