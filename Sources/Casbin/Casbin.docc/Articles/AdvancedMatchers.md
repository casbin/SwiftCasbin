# Advanced Matchers

SwiftCasbin ships with common helpers like ``Util/keyMatch(_:_:)``, ``Util/regexMatch(_:_:)``, and IP-based matchers.

You can register your own functions and reference them by name from the model’s matcher.

```swift
await enforcer.addFunction(
    fname: "keyMatchCustom",
    f: Util.toExpressionFunction(name: "keyMatchCustom") { s1, s2 in
        Util.keyMatch(s1, s2)
    }
)
```

