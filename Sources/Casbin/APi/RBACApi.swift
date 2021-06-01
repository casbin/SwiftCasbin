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

import NIO

extension CoreApi {
    func addPermission(for user:String,permission:[String]) -> EventLoopFuture<Bool> {
        var perm = permission
        perm.insert(user, at: 0)
        return addPolicy(params: perm)
    }
    func addPermissions(for user:String,permissions:[[String]]) -> EventLoopFuture<Bool>{
        let perms = permissions.map { perm -> [String] in
            var _perm = perm
            _perm.insert(user, at: 0)
            return _perm
        }
        return addPolicies(paramss: perms)
    }
    
    func addRole(for user:String,role:String,domain:String?)-> EventLoopFuture<Bool> {
        let params = [user,role,domain].compactMap { $0 }
        return addGroupingPolicy(params: params)
    }
    
    func addRoles(for user:String,roles:[String],domain:String?)-> EventLoopFuture<Bool> {
        let paramss =  roles.map {
            [user,$0,domain].compactMap {$0 }
        }
        return addGroupingPolicies(paramss: paramss)
    }
    func deleteRole(for user:String,role:String,domain:String?)-> EventLoopFuture<Bool> {
        let params = [user,role,domain].compactMap { $0 }
        return removeGroupingPolicy(params: params)
    }
    
    func deleteRoles(for user:String,roles:[String],domain:String?)-> EventLoopFuture<Bool> {
        var params:[String] = []
        if let domain = domain {
            params = [user,"",domain]
        } else {
            params = [user]
        }
        return removeFilteredGroupingPolicy(fieldIndex: 0, fieldValues: params)
    }
    func getRoles(for name:String,domain:String?) -> [String] {
        var roles:[String] = []
        if let ast = model.getModel()["g"]?["g"] {
            roles = ast.rm.getRoles(name: name, domain: domain)
        }
        return roles
    }
    func getUsers(for name:String,domain:String?) -> [String] {
        if let ast = model.getModel()["g"]?["g"] {
            return ast.rm.getUsers(name: name, domain: domain)
        }
        return []
    }
    func hasRole(for name:String,role:String,domain:String?) -> Bool {
        getRoles(for: name, domain: domain).contains(role)
    }
    func deleteUser(name:String) -> EventLoopFuture<Bool> {
        removeFilteredGroupingPolicy(fieldIndex: 0, fieldValues: [name])
    }
    func deleteRole(name:String) -> EventLoopFuture<Bool> {
        removeFilteredGroupingPolicy(fieldIndex: 1, fieldValues: [name])
            .and(removeFilteredPolicy(fieldIndex: 0, fieldValues: [name]))
            .map {
                $0.0 == $0.1
            }
    }
    func deletePermission(for user:String,permission:[String]) -> EventLoopFuture<Bool> {
        var _permission = permission
        _permission.insert(user, at: 0)
        return self.removePolicy(params: _permission)
    }
    func getPermission(for user:String,domain:String?) -> [[String]] {
        getFilteredPolicy(fieldIndex: 0, fieldValues: [user,domain].compactMap { $0 })
    }
    func hasPermission(for user:String,permission:[String]) -> Bool {
        var _permission = permission
        _permission.insert(user, at: 0)
        return hasPolicy(params: _permission)
    }
    
    func getImplicitRoles(for name:String,domain:String?) -> [String] {
        var res:Set<String> = []
        var q:[String] = [name]
        while !q.isEmpty {
            let name = q.remove(at: 0)
            let roles = getRoleManager().getRoles(name: name, domain: domain)
            for r in roles {
                if res.insert(r).inserted {
                    q.append(r)
                }
            }
        }
        return Array(res)
    }
    func getImplicitPermissions(for user:String,domain:String?) -> [[String]] {
        var roles = getImplicitRoles(for: user, domain: domain)
        roles.insert(user, at: 0)
        var res: [[String]]  = []
        roles.forEach {
            res.append(contentsOf: self.getPermission(for: $0, domain: domain))
        }
        return res
    }
    
    func getImplicitUsers(for permission:[String]) -> [String] {
        var subjects = getAllSubjects()
        let roles = getAllRoles()
        let s = roles.flatMap {
            getRoleManager().getUsers(name: $0, domain: nil)
        }
        subjects.append(contentsOf: s)
        
        let users = subjects
            .filter {
                !roles.contains($0)
            }
        var res:[String] = []
        users.forEach { user in
            var req = permission
            req.insert(user, at: 0)
            if case let .success(r) = self.enforce(rvals: req) {
                if r && !res.contains(user) {
                    res.append(user)
                }
            }
        }
        return res
    }
    
    
}
