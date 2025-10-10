# Policy Management

Add, remove, and query policy at runtime using ``Enforcer`` APIs.

```swift
// Add a permission
_ = try await enforcer.addPolicy(params: ["alice", "data1", "read"])

// Remove by filter (domain1, data1)
let removed = try await enforcer.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1", "data1"])
```

RBAC helpers:

```swift
let roles = await enforcer.getRoles(for: "bob", domain: nil)
let actions = await enforcer.getAllActions()
```

