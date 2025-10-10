# ``Casbin``

SwiftCasbin is a Swift 6 authorization library that evaluates access decisions from a model (CONF) and policy rules (CSV) with RBAC, ABAC, and RESTful matchers.

## Overview

SwiftCasbin exposes a single actor, ``Enforcer``, as the concurrency boundary. You load a model and policy via an ``Adapter``, then call ``Enforcer/enforce(_:)`` to authorize a request. The public API is Sendable-friendly and designed for use in highly concurrent systems.

### Quick Start

```swift
import Casbin

let model = try await DefaultModel.from(file: "examples/basic_model.conf")
let adapter = FileAdapter(filePath: "examples/basic_policy.csv")
let e = try await Enforcer(m: model, adapter: adapter)

let ok = try await e.enforce("alice", "data1", "read").get()
```

### Caching

Enable an in-memory LRU cache for repeated requests:

```swift
await e.enableMemoryCache(capacity: 200)
```

### Custom Functions

Register additional matcher functions used by your model:

```swift
await e.addFunction(
    fname: "keyMatchCustom",
    f: Util.toExpressionFunction(name: "keyMatchCustom") { s1, s2 in
        Util.keyMatch(s1, s2)
    }
)
```

## Topics

### Essentials
- <doc:QuickStart>
- <doc:Concurrency>
- <doc:Caching>

### Model and Policy
- ``DefaultModel``
- ``Adapter``
- ``FileAdapter``
- ``MemoryAdapter``

### Roles
- ``RoleManager``
- ``DefaultRoleManager``

### Advanced
- <doc:Adapters>
- <doc:PolicyManagement>
- <doc:AdvancedMatchers>

