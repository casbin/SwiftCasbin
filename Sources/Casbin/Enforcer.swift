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
import Expression
import NIO
import NIOTransportServices
public typealias EventCallback = (EventData,Enforcer) -> Void
public final class Enforcer {
    public var storage: Storage
    public var logger: Logger
    public var model:Model
    public var adapter: Adapter
    public let eventLoopGroup:EventLoopGroup
    public let eventLoopGroupProvider: EventLoopGroupProvider
    
    var symbols: [AnyExpression.Symbol: AnyExpression.SymbolEvaluator] = [:]
    var enabled:Bool = true
    var autoSave: Bool = true
    var autoBuildRoleLinks:Bool = true
    var autoNotifyWatcher:Bool = true
    var events:[Event:[EventCallback]] = [:]
    
    public init (m:Model,adapter:Adapter, _ eventLoopGroupProvider: EventLoopGroupProvider = .createNew) throws {
        self.storage = .init()
        self.model = m
        self.adapter = adapter
        self.eventLoopGroupProvider = eventLoopGroupProvider
        switch eventLoopGroupProvider {
        case .shared(let group):
            self.eventLoopGroup = group
        case .createNew:
            #if canImport(Network)
            if #available(OSX 10.14, iOS 12.0, tvOS 12.0, watchOS 6.0, *) {
                self.eventLoopGroup = NIOTSEventLoopGroup()
            } else {
                self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
            }
            #else
            self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
            #endif
        }
        self.logger = .init(label: "swift.casbin")
        self.core.initialize()
        self.fm.functions.forEach { (key: String, value: @escaping ExpressionFunction) in
            symbols[.function(key, arity: .atLeast(2))] = value
        }
        try registerGFunctions().get()
        self.on(e: .PolicyChange, f: notifyLoggerAndWatcher)
        try loadPolicy().wait()
    }
    public enum EventLoopGroupProvider {
        case shared(EventLoopGroup)
        case createNew
    }
}

extension Enforcer: EventEmitter {
    
    public func on(e: Event, f: @escaping(EventData, Enforcer) -> Void) {
        var fs = self.events.getOrInsert(key: e, with: [])
        fs.append(f)
        events.updateValue(fs, forKey: e)
    }
    
    public func off(e: Event) {
        events.removeValue(forKey: e)
    }
    
    public func emit(e: Event, d: EventData) {
        if let cbs = events[e] {
            cbs.forEach {
                $0(d,self)
            }
        }
    }
    
}

extension Enforcer {
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
        if let astMap = model.getModel()["g"] {
            for (key, ast) in astMap {
                let count = ast.value.filter { $0  == "_" }.count
                if count == 2 {
                    self.symbols[.function(key, arity: 2)] = { args in
                        guard args.count < 2 else {
                            throw CasbinError.OtherErrorMessage("expression args count < 2")
                        }
                        guard let name1 = args[0] as? String,let name2 = args[1] as? String else {
                            throw CasbinError.MATCH_ERROR(.MatchFuntionArgsNotString)
                        }
                        return self.roleManager.hasLink(name1: name1, name2: name2, domain: nil)
                    }
                } else if count == 3 {
                    self.symbols[.function(key, arity: 3)] = { args in
                        guard args.count < 3 else {
                            throw CasbinError.OtherErrorMessage("expression args count < 3")
                        }
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
        }
        return .success(())
    }
    
    func privateEnforce(rvals:[Any]) -> Result<(Bool,[Int]?),Error> {
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
            let policies = pAst.policy
            let (policyLen) = (policies.count)
            var eftStream = eft.newStream(expr: eAst.value, cap: max(policyLen, 1))
            if policyLen == 0 {
                pAst.tokens.forEach {
                    scope[$0] = ""
                }
                let evalResult:Bool = try AnyExpression.init(Util.escapeEval(mAst.value),constants: scope, symbols: symbols).evaluate()
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
                // "r_sub == p_sub && keyMatch(r_obj, p_obj) && regexMatch(r_act, p_act)"
                print(Util.escapeEval(mAst.value))
                let evalResult:Bool = try AnyExpression.init(Util.escapeEval(mAst.value), constants: scope, symbols: symbols).evaluate()
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
    public func enforce(rvals:[Any]) -> Result<Bool,Error> {
        do {
            let (authorized,indices) = try privateEnforce(rvals: rvals).get()
            self.logger.info("Enforce Request;Request:\(rvals),cached:false,Response:\(authorized)")
            
            //            if let indices = indices {
            //                let allRules = try getAst(key: "p").get().policy
            //                let rules = indices.compactMap { y in
            //                    let a = allRules[y].map {
            //                        $0.joined(", ")
            //                    }
            //                }
            //
            //            }
            return .success(authorized)
        } catch  {
            return.failure(error)
        }
    }
    
    public func buildRoleLinks() -> CasbinResult<Void> {
        roleManager.clear()
        return model.buildRolelinks(rm: roleManager)
    }
    
    public func buildIncrementalRoleLinks(eventData:EventData) -> CasbinResult<Void> {
        model.buildIncrementalRoleLinks(rm: roleManager, eventData: eventData)
    }
    
    public func loadPolicy() -> EventLoopFuture<Void> {
        model.clearPolicy()
        return adapter.loadPolicy(m: model).flatMap {
            if self.autoBuildRoleLinks {
                if case .failure(let e) = self.buildRoleLinks() {
                   return self.eventLoopGroup.next().makeFailedFuture(e)
                }
            }
            return self.eventLoopGroup.next().makeSucceededVoidFuture()
        }
    }
    public var isFiltered:Bool {
        return adapter.isFiltered
    }
    
//    public func savePolicy() -> EventLoopFuture<Void> {
//        if isFiltered {
//            preconditionFailure("cannot save filtered policy")
//        }
//        adapter.savePolicy(m: model)
//    }
}

extension Enforcer: CoreApi {
    public func enforce(_ rvals: Any...) -> Result<Bool,Error> {
        enforce(rvals: rvals)
    }
    
    public func addFunction(fname: String, f: @escaping ExpressionFunction) {
        fm.addFuntion(name: fname, function: f)
        symbols[.function(fname, arity: .atLeast(2))] = f
    }
    
    
    public func getRoleManager() -> RoleManager {
        roleManager
    }
    
    public func setRoleManager(rm:RoleManager) -> CasbinResult<Void> {
        self.roleManager = rm
        if autoBuildRoleLinks {
            do {
                try self.buildRoleLinks().get()
            } catch  {
                return .failure(error as! CasbinError)
            }
        }
        return registerGFunctions()
    }
    
    public func setModel(_ model: Model) -> EventLoopFuture<Void> {
        self.model = model
        return loadPolicy()
    }
    
    public func setAdapter(_ adapter: Adapter) -> EventLoopFuture<Void> {
        self.adapter = adapter
        return loadPolicy()
    }
    
    public func loadFilterdPolicy(_ f: Filter) -> EventLoopFuture<Void> {
        model.clearPolicy()
        return adapter.loadFilteredPolicy(m: model, f: f).flatMap {
            if self.autoBuildRoleLinks {
                if case .failure(let e) = self.buildRoleLinks() {
                   return self.eventLoopGroup.next().makeFailedFuture(e)
                }
            }
            return self.eventLoopGroup.next().makeSucceededVoidFuture()
        }
    }
    
    public var isEnabled: Bool {
        self.enabled
    }
    
    public func savePolicy() -> EventLoopFuture<Void> {
        if isFiltered {
            eventLoopGroup.next().preconditionInEventLoop(file: #file, line: #line)
        }
        return adapter.savePolicy(m: model).map { _ in
            var policies = self.getAllPolicy()
            let gpolicies = self.getAllGroupingPolicy()
            policies.append(contentsOf: gpolicies)
            self.emit(e: Event.PolicyChange, d: .SavePolicy(policies))
        }
    }
    
    public func clearPolicy() -> EventLoopFuture<Void> {
        if autoSave {
            return adapter.clearPolicy().map { [self] _ in
                model.clearPolicy()
                emit(e: .PolicyChange, d: .ClearCache)
            }
        }
        model.clearPolicy()
        emit(e: .PolicyChange, d: .ClearCache)
        return eventLoopGroup.next().makeSucceededVoidFuture()
    }
    
    public func enableAutoSave(auto: Bool) {
        self.autoSave = auto
    }
    
    public func enableEnforce(enabled: Bool) {
        self.enabled = enabled
        
    }
    
    public func enableAutoBuildRoleLinks(auto: Bool) {
        autoBuildRoleLinks = auto
    }
    
    public func enableAutoNotifyWatcher(auto: Bool) {
        autoNotifyWatcher = auto
    }
    
    public func hasAutoSaveEnable() -> Bool {
        autoSave
    }
    
    public func hasAutoNotifyWatcherEnabled() -> Bool {
        autoNotifyWatcher
    }
    
    public func hasAutoBuildRoleLinksEnabled() -> Bool {
        autoBuildRoleLinks
    }
    
    
}


