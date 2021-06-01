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
import Logging
public struct Storage {
    var storage: [ObjectIdentifier: AnyStorageValue]

    struct Value<T>:AnyStorageValue {
        
        var value: T
    }

    public init() {
        self.storage = [:]
    }

    public mutating func clear() {
        self.storage = [:]
    }

    public subscript<Key>(_ key: Key.Type) -> Key.Value?
        where Key: StorageKey
    {
        get {
            self.get(Key.self)
        }
        set {
            self.set(Key.self, to: newValue)
        }
    }

    public func contains<Key>(_ key: Key.Type) -> Bool {
        self.storage.keys.contains(ObjectIdentifier(Key.self))
    }

    public func get<Key>(_ key: Key.Type) -> Key.Value?
        where Key: StorageKey
    {
        guard let value = self.storage[ObjectIdentifier(Key.self)] as? Value<Key.Value> else {
            return nil
        }
        return value.value
    }

    public mutating func set<Key>(
        _ key: Key.Type,
        to value: Key.Value?
    )
        where Key: StorageKey
    {
        let key = ObjectIdentifier(Key.self)
        if let value = value {
            self.storage[key] = Value(value: value)
        } else if self.storage[key] != nil {
            self.storage[key] = nil
        }
    }

}

protocol AnyStorageValue {
    
}

public protocol StorageKey {
    associatedtype Value
}
