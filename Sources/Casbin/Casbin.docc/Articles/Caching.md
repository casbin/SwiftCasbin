# Caching

SwiftCasbin provides an optional in-memory LRU cache integrated with ``Enforcer``. It reduces cost for repeated requests with identical tuples.

## Enable

```swift
await enforcer.enableMemoryCache(capacity: 200)
```

## How it works

- O(1) get/set using a dictionary + doubly-linked list, synchronized by `Mutex`.
- Cache keys are computed from the `Sendable` arguments passed to ``Enforcer/enforce(_:)``.

