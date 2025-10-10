# Quick Start

This article shows the minimal steps to authorize a request with SwiftCasbin.

## Load a model and policy

```swift
import Casbin

let model = try await DefaultModel.from(file: "examples/basic_model.conf")
let adapter = FileAdapter(filePath: "examples/basic_policy.csv")
let enforcer = try await Enforcer(m: model, adapter: adapter)
```

## Enforce

Pass Sendable arguments (subject, object, action by default):

```swift
let allowed = try await enforcer.enforce("alice", "data1", "read").get()
```

## Enable cache (optional)

```swift
await enforcer.enableMemoryCache(capacity: 200)
```

