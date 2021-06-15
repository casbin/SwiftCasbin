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

public final class DefaultRoleManager {
   
    static let defaultDomain = "casbin::default"
    var allDomains: [String: [String:Role]]  = [:]
    var maxHierarchyLevel :Int
    var cache:Cache? = nil
    var matchingFunc: MatchFunction?  = nil
    var domainMatchingFunc:MatchFunction? = nil
    
    
    /// In order to use a specific role name matching function, set explicitly the role manager on
    /// the Enforcer and rebuild role links (you can optimize by using minimal enforcer constructor)
    /// - Parameters:
    ///   - allDomains:
    ///   - maxHierarchyLevel: the maximized allowed RBAC hierarchy level.
    public init(maxHierarchyLevel: Int,cache:Cache? = nil) {
        self.maxHierarchyLevel = maxHierarchyLevel
    }
    
    func createRole(name:String,domain:String?) -> Role {
        let domain = domain ?? Self.defaultDomain
        var created = false
        var roles = allDomains.getOrInsert(key: domain, with: [:])
        let role = roles.getOrInsert(key: name) {
            created = true
            return Role.init(name: name)
        }
        
        if let roleMatchingFn = matchingFunc,created == true {
            var added = false
            for (key,value) in roles {
                if key != name && roleMatchingFn(name,key) && role.addRole(role: value) {
                    added = true
                }
            }
            if added {
                if let cache = self.cache {
                    cache.clear()
                }
            }
        }
        allDomains.updateValue(roles, forKey: domain)
        return role
    }
    func matchedDomains(domain:String?) -> [String] {
        let domain = domain ?? Self.defaultDomain
        if let domainMatchingFn = domainMatchingFunc {
           return allDomains.keys.compactMap { key -> String? in
            if domainMatchingFn(domain,key) {
                    return key
                } else {
                    return nil
                }
            }
        } else {
           return allDomains[domain] == nil ? [] : [domain]
        }
    }
    func createTempRole(name:String,domain: String?) -> Role {
        let role = createRole(name: name, domain: domain)
        let matchedDomains = matchedDomains(domain: domain)
        for domain in matchedDomains.filter({ $0 != domain}) {
            for directRole in createRole(name: name, domain: domain).roles {
               _ = role.addRole(role: directRole)
            }
        }
        return role
    }
    func hasRole(name:String,domain:String?) -> Bool {
        let matchedDomains = matchedDomains(domain: domain)
        return !matchedDomains.isEmpty && matchedDomains.contains(where: { domain in
            if let roles = allDomains[domain] {
                if roles.keys.contains(name) {
                    return true
                }
                if let roleMatchingFn = self.matchingFunc {
                    return roles.keys.contains {
                        roleMatchingFn(name,$0)
                    }
                }
                return false
            }
            return false
        })
    }
  
}


extension DefaultRoleManager : RoleManager {
    
    public func clear() -> Void {
        allDomains = [:]
        if let cache = self.cache {
            cache.clear()
        }
    }
    
    public func addLink(name1: String, name2: String, domain: String?)  {
        if name1 == name2 {
            return
        }
        let role1 = createRole(name: name1, domain: domain)
        let role2 = createRole(name: name2, domain: domain)
        if !role1.addRole(role: role2) {
            if let cache = cache {
                cache.clear()
            }
        }
    }
    
    public func deleteLink(name1: String, name2: String, domain: String?) -> CasbinResult<Void> {
        if !self.hasRole(name: name1, domain: domain)
            || !self.hasRole(name: name2, domain: domain) {
            return .failure(.RBAC_ERROR(.NamesNotFound))
        }
        let role1 = createRole(name: name1, domain: domain)
        let role2 = createRole(name: name2, domain: domain)
        role1.deleteRole(role: role2)
        if let cache = self.cache  {
            cache.clear()
        }
        return .success(())
    }
    
    public func hasLink(name1: String, name2: String, domain: String?) -> Bool {
        if name1 == name2 {
            return true
        }
        let makeCacheKey = { () -> Int in
            var hasher = Hasher.init()
            name1.hash(into: &hasher)
            name2.hash(into: &hasher)
            (domain ?? Self.defaultDomain).hash(into: &hasher)
            return hasher.finalize()
        }
        var cacheKey: Int = 0
        if let cache = self.cache {
            cacheKey = makeCacheKey()
            if let res = cache.get(key: cacheKey, as: Bool.self) {
                return res
            }
        }
        let hasRoles = hasRole(name: name1, domain: domain)
                      && hasRole(name: name2, domain: domain)
        var res :Bool {
            if domainMatchingFunc != nil {
             return hasRoles && self.createTempRole(name: name1, domain: domain)
                    .hasRole(name: name2, hierarchyLevel: maxHierarchyLevel)
            } else {
             return hasRoles && self.createRole(name: name1, domain: domain)
                    .hasRole(name: name2, hierarchyLevel: maxHierarchyLevel)
            }
        }
        if let cache = self.cache {
            cache.set(key: cacheKey, value: res)
        }
        return res
        
    }
    
    public func getRoles(name: String, domain: String?) -> [String] {
        if !self.hasRole(name: name, domain: domain) {
            return []
        }
        return createTempRole(name: name, domain: domain).rolesStringList
    }
    
    public func getUsers(name: String, domain: String?) -> [String] {
        let matchedDomains = matchedDomains(domain: domain)
        let res = matchedDomains.reduce(Set<String>()) { acc, x in
            var users : [String] {
                if let roles = allDomains[x] {
                   return roles.values.compactMap { role -> String? in
                        if role.hasDirectRole(name: name) {
                            return role.name
                        } else {
                            return nil
                        }
                    }
                } else {
                    return []
                }
            }
            
            return acc.union(users)
            
        }
        return Array(res)
    }
     
}
