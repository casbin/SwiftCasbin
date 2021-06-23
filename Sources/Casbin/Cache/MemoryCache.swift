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

public final class DefaultCache:Cache {
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

final class LruCache<Key:Hashable,Value> {
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
    private var storage:[Key:ListNode] = [:]
    var capacity = 0
    private var lock:Lock
    
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
    /// Remove Node in the Double Linked-list.
        private func remove(node: ListNode) {
            self.lock.lock()
            defer { self.lock.unlock() }
            node.prevNode?.nextNode = node.nextNode
            node.nextNode?.prevNode = node.prevNode
            guard let key = node.key else { return }
            storage.removeValue(forKey: key)
     }
    func clear() {
        self.lock.lock()
        defer { self.lock.unlock() }
        self.storage = [:]
    }
    /// insertion is always fullfilled on the Head side.
        private func insertToHead(node: ListNode) {
            self.lock.lock()
            defer { self.lock.unlock() }
            head.nextNode?.prevNode = node
            node.nextNode = head.nextNode
            node.prevNode = head
            head.nextNode = node
            guard let key = node.key else { return }
            storage.updateValue(node, forKey: key)
        }
    /// When the cache hit happen, remove the node what you get and insert to Head side again.
       func getValue(forKey key: Key) -> Value? {
        self.lock.lock()
        defer { self.lock.unlock() }
           if !storage.contains(where: { $0.key == key }) {
               return nil
           }
           guard let node = storage[key] else { return nil }
           remove(node: node)
           insertToHead(node: node)
           return node.value
       }
    /// Push your value and if there is same value, remove that automatically.
        /// if not, remove Least Recently Used Node and push new node.
        func setValue(value: Value, forKey key: Key) {
            self.lock.lock()
            defer { self.lock.unlock() }
            let newNode = ListNode(key: key, value: value)
            if storage.contains(where: { $0.key == key }){
                guard let oldNode = storage[key] else { return }
                remove(node: oldNode)
            } else {
                if storage.count >= capacity {
                    guard let tailNode = tail.prevNode else { return }
                    remove(node: tailNode) // remove Least Recently Used Node
                }
            }
            insertToHead(node: newNode)
        }
}
