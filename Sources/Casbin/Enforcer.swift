// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Logging
@preconcurrency import Expression
import Foundation

/// A callback signature for receiving asynchronous policy and cache events.
public typealias EventCallback = @Sendable (EventData, Enforcer) async -> Void

/// The main entry point for authorization decisions.
///
/// Enforcer is an actor that evaluates requests against a loaded model and policy.
/// Create an instance with a ``Model`` and an ``Adapter`` and then call
/// ``enforce(_:)`` to authorize requests. Most APIs are `async` and accept
/// `Sendable` values to be concurrency-friendly.
public actor Enforcer {
    public var logger: Logger
    public var model: Model
    public var adapter: Adapter
    public var watcher: Watcher?
    public var roleManager: RoleManager
    public var eft: Effector
    public var cache: Cache?

    var fm: FunctionMap
    var symbols: [AnyExpression.Symbol: AnyExpression.SymbolEvaluator] = [:]
    var enabled: Bool = true
    var logEnabled: Bool = true
    var autoSave: Bool = true
    var autoBuildRoleLinks: Bool = true
    var autoNotifyWatcher: Bool = true
    var events: [Event:[EventCallback]] = [:]

    /// Initializes a new enforcer.
    /// - Parameters:
    ///   - m: The loaded authorization ``Model``.
    ///   - adapter: The ``Adapter`` used to load and persist policy.
    public init(m: Model, adapter: Adapter) async throws {
        self.model = m
        self.adapter = adapter
        self.logger = .init(label: "swift.casbin")
        self.roleManager = DefaultRoleManager(maxHierarchyLevel: 10)
        self.eft = DefaultEffector()
        self.watcher = nil
        self.fm = FunctionMap.default()
        self.cache = nil

        for (key, value) in self.fm.functions {
            symbols[.function(key, arity: .atLeast(2))] = value
        }

        symbols[.infix("in")] = { args in
            guard let left = args[0] as? String,
                  let right = args[1] as? Array<String> else {
                throw CasbinError.MATCH_ERROR(.MatchFuntionArgsNotString)
            }
            return right.contains(left)
        }

        _ = try registerGFunctions().get()
        if self.cache != nil {
            let cb: EventCallback = { data, ef in await Casbin.clearCache(eventData: data, e: ef) }
            var fs = self.events.getOrInsert(key: .ClearCache, with: [])
            fs.append(cb)
            self.events.updateValue(fs, forKey: .ClearCache)
        }
        let mgmt: EventCallback = { data, ef in await Casbin.notifyLoggerAndWatcher(eventData: data, e: ef) }
        var ps = self.events.getOrInsert(key: .PolicyChange, with: [])
        ps.append(mgmt)
        self.events.updateValue(ps, forKey: .PolicyChange)
        try await loadPolicy()
    }
}

extension Enforcer {
    /// Registers an async event listener.
    public func on(e: Event, f: @escaping @Sendable (EventData, Enforcer) async -> Void) {
        var fs = self.events.getOrInsert(key: e, with: [])
        fs.append(f)
        events.updateValue(fs, forKey: e)
    }
    /// Removes all listeners for a given event type.
    public func off(e: Event) {
        events.removeValue(forKey: e)
    }
    /// Emits an event to all listeners.
    public func emit(e: Event, d: EventData) async {
        if let cbs = events[e] {
            for cb in cbs { await cb(d, self) }
        }
    }
}

extension Enforcer {
    // Helpers used by event callbacks (class context)
    func notifyLoggerAndWatcher(eventData: EventData) {
        if enableLog {
            logger.printMgmtLog(e: eventData, level: logger.logLevel)
        }
        if let w = watcher { w.update(eventData: eventData) }
    }
    func clearCache() { cache?.clear() }
    private func getAst(key:String) -> CasbinResult<Assertion> {
        var e1 = CasbinError.ModelError.Other("un match key:\(key)")
        var e2 = e1
        switch key {
        case "r":
            e1 = .R("Missing request definition in conf file")
            e2 = .R("Missing request section in conf file")
        case "p":
            e1 = .P("Missing policy definition in conf file")
            e2 = .P("Missing policy section in conf file")
        case "m":
            e1 = .P("Missing matcher definition in conf file")
            e2 = .P("Missing matcher section in conf file")
        case "e":
            e1 = .P("Missing effector definition in conf file")
            e2 = .P("Missing effector section in conf file")
        default:
            break
        }
   
        if let asts = self.model.getModel()[key] {
            if let ast = asts[key] {
                return .success(ast)
            } else {
                return .failure(.MODEL_ERROR(e2))
            }
        } else {
            return .failure(.MODEL_ERROR(e1))
        }
    }
    func registerGFunctions() -> CasbinResult<()> {
        guard let astMap = model.getModel()["g"] else { return .success(()) }
        for (key, ast) in astMap {
            let count = ast.value.filter { $0  == "_" }.count
            if count == 2 {
                self.symbols[.function(key, arity: 2)] = { args in
                    guard let name1 = args[0] as? String, let name2 = args[1] as? String else {
                        throw CasbinError.MATCH_ERROR(.MatchFuntionArgsNotString)
                    }
                    return self.roleManager.hasLink(name1: name1, name2: name2, domain: nil)
                }
            } else if count == 3 {
                self.symbols[.function(key, arity: 3)] = { args in
                    guard let name1 = args[0] as? String,
                          let name2 = args[1] as? String,
                          let domain = args[2] as? String else {
                        throw CasbinError.MATCH_ERROR(.MatchFuntionArgsNotString)
                    }
                    return self.roleManager.hasLink(name1: name1, name2: name2, domain: domain)
                }
            } else {
                return .failure(CasbinError.MODEL_ERROR(.P(#"the number of "_" in role definition should be at least 2"#)))
            }
        }
        return .success(())
    }
    nonisolated private func makeExpression(scope:[String:Any], parsed:ParsedExpression, symbolsSnapshot: [AnyExpression.Symbol: AnyExpression.SymbolEvaluator]) -> AnyExpression {
       return .init(parsed, impureSymbols: { symbol  in
             if case let .function(s, arity: _) = symbol,s == "eval" {
                return { [self] args -> Any? in
                    guard let ex = args[0] as? String else {
                        throw CasbinError.MATCH_ERROR(.MatchFuntionArgsNotString)
                    }
                    let expString = Util.escapeAssertion(ex)
                    let exp = Expression.parse(expString)
                    return try? makeExpression(scope: scope, parsed: exp, symbolsSnapshot: symbolsSnapshot).evaluate()
                }
            }
            if case let .variable(s) = symbol,!(s.hasPrefix("\"") && s.hasSuffix("\"")) {
                let sp = s.split(separator: ".").map { String($0)}
                if sp.count > 1 {
                    var objcet = scope[sp[0]]
                    for i in 1..<sp.count {
                        objcet = getMirrorValue(label: sp[i], value: objcet as Any)
                    }
                  
                    return {_ in objcet as Any}
                }
                return {_ in scope[sp[0]] as Any}
            }
            if case .function = symbol, symbolsSnapshot.keys.contains(symbol) {
                return symbolsSnapshot[symbol]
            }
            if case .infix(let s) = symbol,s == "in" {
                return symbolsSnapshot[symbol]
            }
            return nil
        })
    }
    nonisolated private func getMirrorValue(label:String,value:Any) -> Any? {
        let mirror = Mirror.init(reflecting: value)
        let children = mirror.children
        if children.isEmpty {
            return value
        }
        
        for child in children {
            
            if child.label == "some" {
                let vMirror = Mirror.init(reflecting: child.value)
                let vchildren = vMirror.children
                if vchildren.isEmpty {
                    return child.value
                }
                for vchild in vchildren {
                    if vchild.label == label {
                        return vchild.value
                    }
                }
            }
        }
        return nil
    }
    
    func privateEnforce(rvals:[any Sendable]) -> Result<(Bool,[Int]?),Error> {
        if !self.enabled {
            return .success((true, nil))
        }
        var scope:[String:Any] = [:]
        do {
            let rAst = try getAst(key: "r").get()
            let pAst = try getAst(key: "p").get()
            let mAst = try getAst(key: "m").get()
            let eAst = try getAst(key: "e").get()
            
            if rAst.tokens.count != rvals.count {
                return .failure(CasbinError.MODEL_ERROR(.R("Request doesn't match request definition. expected length: \(rAst.tokens.count), found length \(rvals.count)")))
            }
            rAst.tokens.enumerated().forEach { (index,token) in
                scope[token] = rvals[index]
                
            }
         
            let ex = Expression.parse(Util.escapeEval(mAst.value))
            let symbolsSnapshot = self.symbols
            let policies = pAst.policy
            let (policyLen) = (policies.count)
            var eftStream = eft.newStream(expr: eAst.value, cap: max(policyLen, 1))
            if policyLen == 0 {
                pAst.tokens.forEach {
                    scope[$0] = ""
                }
                let eval = makeExpression(scope: scope, parsed: ex, symbolsSnapshot: symbolsSnapshot)
                let evalResult:Bool = try eval.evaluate()
                let eft = evalResult ? Effect.Allow : .Indeterminate
                _ = eftStream.pushEffect(eft: eft)
                return .success((eftStream.next(), nil))
            }
            for pvals in policies {
                if pAst.tokens.count != pvals.count {
                    return .failure(CasbinError.MODEL_ERROR(.P("Policy doesn't match policy definition. expected length: \(pAst.tokens.count), found length \(pvals.count)")))
                }
                pAst.tokens.enumerated().forEach { (index,token) in
                    scope[token] = pvals[index]
                }
                let eval = makeExpression(scope: scope, parsed: ex, symbolsSnapshot: symbolsSnapshot)
                let evalResult:Bool = try eval.evaluate()

                let eft:Effect = { () -> Effect in
                    if let i = pAst.tokens.firstIndex(of: "p_eft") {
                        if evalResult {
                            let pEft = pvals[i]
                            if pEft == "deny" {
                                return Effect.Deny
                            } else if pEft == "allow" {
                                return Effect.Allow
                            } else {
                                return Effect.Indeterminate
                            }
                        } else {
                            return Effect.Indeterminate
                        }
                    } else {
                        if evalResult {
                            return Effect.Allow
                        } else {
                            return Effect.Indeterminate
                        }
                    }
                }()
                if eftStream.pushEffect(eft: eft) {
                    break
                }
            }
            return .success((eftStream.next(), eftStream.explain()))
            
        } catch  {
            return .failure(error )
        }
        
    }
    public func enforce(rvals:[any Sendable]) -> Result<Bool,Error> {
        do {
            var _authorized:Bool
            var _cached: Bool = false
            var _indices:[Int]?
            
            if self.cache != nil {
                var hasher = Hasher.init()
                rvals.forEach {
                    if let hash = $0 as? AnyHashable {
                        hasher.combine(hash)
                    }
                }
                let cacheKey = hasher.finalize()
                let (authorized,cached,indices) = try cachedPrivateEnforce(rvals: rvals, cacheKey: cacheKey).get()
                _authorized = authorized
                _cached = cached
                _indices = indices
            }
            let (authorized,indices) = try privateEnforce(rvals: rvals).get()
            _authorized = authorized
            _indices = indices
            if logEnabled {
                self.logger.printEnforceLog(
                    rvals: rvals.compactMap({ $0 as? String }),
                    cached: _cached,
                    authorized: _authorized,
                    level: logger.logLevel)
                if let indices = _indices {
                    if case let .success(ast) = self.getAst(key: "p") {
                       let  allRules = ast.policy
                        let rules = indices.compactMap {
                        allRules[$0].joined(separator: ", ")
                        }
                    self.logger.printExplainLog(rules: rules, level: logger.logLevel)
                    }
                }
            }
            return .success(authorized)
        } catch  {
            return.failure(error)
        }
    }
    
    /// Re-builds role links from the current model and policy.
    public func buildRoleLinks() -> CasbinResult<Void> {
        roleManager.clear()
        return model.buildRolelinks(rm: roleManager)
    }
    
    public func buildIncrementalRoleLinks(eventData:EventData) -> CasbinResult<Void> {
        model.buildIncrementalRoleLinks(rm: roleManager, eventData: eventData)
    }
    
    /// Loads policy from the adapter, optionally building role links.
    public func loadPolicy() async throws {
        model.clearPolicy()
        try await adapter.loadPolicy(m: model)
        if self.autoBuildRoleLinks { try self.buildRoleLinks().get() }
    }
    public var isFiltered:Bool {
        return adapter.isFiltered
    }
    
}

extension Enforcer {
    /// Returns the in-memory result cache if enabled.
    public func getCache() -> Cache? { self.cache }
    /// Updates the cache capacity if caching is enabled.
    public func setCapacity(_ c: Int) { self.cache?.setCapacity(c) }
    
    /// Enables or disables internal status logging.
    public var enableLog: Bool {
        get {
            self.logEnabled
        }
        set {
            self.logEnabled = newValue
        }
    }
    
    /// Evaluates a request against the model and policy.
    /// - Parameter rvals: Request values (e.g. subject, object, action).
    /// - Returns: `true` when authorized; `false` otherwise.
    public func enforce(_ rvals: any Sendable...) -> Result<Bool,Error> {
        enforce(rvals: rvals)
    }
    
    /// Registers a custom matcher function usable from the model.
    public func addFunction(fname: String, f: @escaping ExpressionFunction) {
        fm.addFuntion(name: fname, function: f)
        symbols[.function(fname, arity: .atLeast(2))] = f
    }
    
    
    /// Returns the current role manager.
    public func getRoleManager() -> RoleManager {
        roleManager
    }
    
    /// Sets the role manager and (optionally) rebuilds links.
    public func setRoleManager(rm:RoleManager) -> CasbinResult<Void> {
        self.roleManager = rm
        if autoBuildRoleLinks {
            switch self.buildRoleLinks() {
            case .success:
                break
            case .failure(let e):
                return .failure(e)
            }
        }
        return registerGFunctions()
    }
    
    /// Replaces the current model and reloads policy.
    public func setModel(_ model: Model) async throws {
        self.model = model
        try await loadPolicy()
    }

    /// Replaces the current adapter and reloads policy.
    public func setAdapter(_ adapter: Adapter) async throws {
        self.adapter = adapter
        try await loadPolicy()
    }

    /// Loads a filtered subset of policy.
    public func loadFilterdPolicy(_ f: Filter) async throws {
        model.clearPolicy()
        try await adapter.loadFilteredPolicy(m: model, f: f)
        if self.autoBuildRoleLinks { try self.buildRoleLinks().get() }
    }
    
    /// Indicates whether enforcement is enabled.
    public var isEnabled: Bool {
        self.enabled
    }
    
    /// Persists the current policy using the adapter and emits a change event.
    public func savePolicy() async throws {
        try await adapter.savePolicy(m: model)
        var policies = self.getAllPolicy()
        let gpolicies = self.getAllGroupingPolicy()
        policies.append(contentsOf: gpolicies)
        await self.emit(e: Event.PolicyChange, d: .SavePolicy(policies))
    }

    /// Clears all policy. If `autoSave` is enabled, removes it from the adapter as well.
    public func clearPolicy() async throws {
        if autoSave {
            try await adapter.clearPolicy()
            model.clearPolicy()
            await emit(e: .PolicyChange, d: .ClearCache)
        } else {
            model.clearPolicy()
            await emit(e: .PolicyChange, d: .ClearCache)
        }
    }
    
    /// Enables or disables automatic persistence when policy changes.
    public func enableAutoSave(auto: Bool) {
        self.autoSave = auto
    }
    
    /// Enables or disables enforcement.
    public func enableEnforce(enabled: Bool) {
        self.enabled = enabled
        if logEnabled {
            logger.printStatusLog(enabled: enabled)
        }
        
    }
    
    /// Enables or disables automatic role-link rebuilding after changes.
    public func enableAutoBuildRoleLinks(auto: Bool) {
        autoBuildRoleLinks = auto
    }
    
    /// Enables or disables automatic watcher notifications after changes.
    public func enableAutoNotifyWatcher(auto: Bool) {
        autoNotifyWatcher = auto
    }
    
    /// Returns whether auto-save is enabled.
    public func hasAutoSaveEnable() -> Bool { autoSave }
    /// Returns whether auto-notify-watcher is enabled.
    public func hasAutoNotifyWatcherEnabled() -> Bool { autoNotifyWatcher }
    /// Returns whether auto-build-role-links is enabled.
    public func hasAutoBuildRoleLinksEnabled() -> Bool { autoBuildRoleLinks }
}
