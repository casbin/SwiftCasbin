# Concurrency

SwiftCasbin targets Swift 6 concurrency:

- ``Enforcer`` is an actor and the primary isolation boundary for the library.
- Public APIs accept `Sendable` where needed. For example, ``Enforcer/enforce(_:)`` takes `any Sendable...` values.
- Small, hot data structures (like the in-memory LRU cache and the model’s internal maps) use `Synchronization.Mutex` for minimal overhead.
- No `@unchecked Sendable` is used.

## Events

You can observe policy changes via async callbacks:

```swift
await enforcer.on(e: .PolicyChange) { event, e in
    // handle event
}
```

