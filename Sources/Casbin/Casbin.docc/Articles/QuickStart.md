# Quick Start

Minimal example to authorize a request with SwiftCasbin.

```swift
import Casbin

let model = try DefaultModel.from(text: ""
    + "[request_definition]\n"
    + "r = sub, obj, act\n"
    + "[policy_definition]\n"
    + "p = sub, obj, act\n"
    + "[policy_effect]\n"
    + "e = some(where (p.eft == allow))\n"
    + "[matchers]\n"
    + "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"
)
let adapter = MemoryAdapter()
let e = try Enforcer(m: model, adapter: adapter)
_ = try e.addPolicy(params: ["alice", "data1", "read"]).get()
let ok = try e.enforce("alice", "data1", "read").get()
```
