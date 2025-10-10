# Adapters

Adapters load and save policy to a backing store.

## FileAdapter

```swift
let adapter = FileAdapter(filePath: "examples/basic_policy.csv")
```

## MemoryAdapter

```swift
let adapter = MemoryAdapter()
```

## Filtered loads

```swift
let filter = Filter(p: ["", "domain1"], g: ["", "", "domain1"])
try await enforcer.loadFilterdPolicy(filter)
```

