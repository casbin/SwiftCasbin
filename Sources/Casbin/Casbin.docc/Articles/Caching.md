# Caching

SwiftCasbin includes an optional in-memory cache for enforce results.

- Enable: `e.enableMemoryCache(capacity: 200)`
- Clear: `e.getCache()?.clear()`
