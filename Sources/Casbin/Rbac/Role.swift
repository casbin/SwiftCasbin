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


/// represents the data structure for a role in RBAC
final class Role:CustomDebugStringConvertible {
    var debugDescription: String {
        var names = ""
        roles.enumerated().forEach { (index,role) in
            if index == 0 {
                names.append(role.name)
            }else {
                names.append("," + role.name)
            }
        }
        return name + "<" + names
    }
    
    var rolesStringList:[String] {
        roles.map { $0.name }
    }
    
    private var _name:String
    var roles:[Role]
    
    init(name:String) {
        self._name = name
        self.roles = []
    }
    var name:String {
        self._name
    }
    
    func addRole(role:Role) -> Bool {
        let noExist = !isExist(role: role)
        if noExist {
           roles.append(role)
        }
        return noExist
    }
    func isExist(role:Role) -> Bool {
        roles.contains {
            $0.name == role.name
        }
    }
    func deleteRole(role:Role) {
         roles.removeAll {
            $0.name == role.name
        }
    }
    
    func hasRole(name: String,hierarchyLevel:Int) -> Bool {
        if self.name == name {
            return true
        }
        if hierarchyLevel <= 0 {
            return false
        }
        return roles.contains {
            $0.hasRole(name: name, hierarchyLevel: hierarchyLevel - 1)
        }
    }
    func hasDirectRole(name:String) -> Bool {
        roles.contains {
            $0.name == name
        }
    }
    
}
