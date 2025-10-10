# Policy Management

Add or remove policy at runtime.

```swift
_ = try e.addPolicy(params: ["alice", "data1", "read"]).get()
let removed = try e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"]).get()
```
