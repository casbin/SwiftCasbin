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

/// A thread-safe synchronization primitive that protects access to a mutable value
public final class Mutex<T>: @unchecked Sendable {
    private var value: T
    private let nsLock = NSLock()

    public init(_ value: T) {
        self.value = value
    }

    @discardableResult
    public func withLock<R>(_ body: (inout T) throws -> R) rethrows -> R {
        nsLock.lock()
        defer { nsLock.unlock() }
        return try body(&value)
    }
}
